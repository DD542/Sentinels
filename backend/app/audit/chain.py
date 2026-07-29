from __future__ import annotations
import hashlib
import hmac
import json
import time

from ..config import get_settings
from .. import db
from .. import logs
from . import crypto

settings = get_settings()
_log = logs.get_logger("audit")
_HMAC_KEY = bytes.fromhex(settings.audit_hmac_key)
_GENESIS = "0" * 64

# Cache mémoire (toujours actif ; source de vérité si pas de DB).
_CHAIN: list[dict] = []


def _seal(payload: dict, prev_hash: str) -> str:
    material = json.dumps(payload, sort_keys=True) + prev_hash
    return hmac.new(_HMAC_KEY, material.encode(), hashlib.sha256).hexdigest()


# ============================================================
# Keyring — une clé de données (DEK) aléatoire par entity_id.
# Détruire la DEK = crypto-shredding (RGPD art. 17).
# ============================================================

def _get_or_create_key_mem(entity_id: str) -> bytes | None:
    """Repli mémoire : renvoie la DEK en clair de l'entité, en la
    créant si besoin. None seulement si l'entité a été oubliée."""
    wrapped = crypto._KEYRING.get(entity_id)
    if wrapped is None:
        if entity_id in _SHREDDED:
            return None
        dek = crypto.new_dek()
        crypto._KEYRING[entity_id] = crypto.wrap_key(dek)
        return dek
    return crypto.unwrap_key(wrapped)


# Entités oubliées en mémoire (repli sans DB) : on refuse de recréer une clé.
_SHREDDED: set[str] = set()


async def _get_or_create_key_db(entity_id: str) -> bytes | None:
    """Version persistée : la DEK enveloppée vit dans `audit_keys`.
    Si la ligne a été supprimée (oubli), renvoie None."""
    async with db.pool().acquire() as con:
        row = await con.fetchrow(
            "SELECT wrapped FROM audit_keys WHERE entity_id = $1", entity_id)
        if row is not None:
            return crypto.unwrap_key(row["wrapped"])
        # Jamais vue : on crée. INSERT ... ON CONFLICT DO NOTHING gère la
        # course entre deux requêtes concurrentes sur la même entité.
        dek = crypto.new_dek()
        wrapped = crypto.wrap_key(dek)
        inserted = await con.fetchrow(
            "INSERT INTO audit_keys (entity_id, wrapped) VALUES ($1, $2) "
            "ON CONFLICT (entity_id) DO NOTHING RETURNING wrapped", entity_id, wrapped)
        if inserted is None:
            # Une autre requête a inséré entre-temps : on relit sa clé.
            row = await con.fetchrow(
                "SELECT wrapped FROM audit_keys WHERE entity_id = $1", entity_id)
            return crypto.unwrap_key(row["wrapped"]) if row else None
        return dek


def _build_entry(action, entity_type, entity_id, cipher, prev_hash) -> dict:
    entry = {
        "ts": time.time(),
        "action": action,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "cipher": cipher,
        "prev_hash": prev_hash,
    }
    entry["hash"] = _seal(entry, prev_hash)
    return entry


# ============================================================
# API synchrone (repli mémoire, conservée pour compat)
# ============================================================

def append(action: str, entity_type: str, entity_id: str, detail: dict) -> dict:
    prev_hash = _CHAIN[-1]["hash"] if _CHAIN else _GENESIS
    dek = _get_or_create_key_mem(entity_id)
    # dek None (entité oubliée) : on scelle un marqueur non déchiffrable.
    cipher = crypto.encrypt_detail(detail, dek) if dek else "SHREDDED"
    entry = _build_entry(action, entity_type, entity_id, cipher, prev_hash)
    _CHAIN.append(entry)
    return entry


def verify_integrity() -> bool:
    prev = _GENESIS
    for entry in _CHAIN:
        expected = _seal({k: v for k, v in entry.items() if k != "hash"}, prev)
        if entry["hash"] != expected or entry["prev_hash"] != prev:
            return False
        prev = entry["hash"]
    return True


def read_detail(entry: dict) -> dict | None:
    """Déchiffre le détail d'une entrée si sa clé existe encore.
    None = entité oubliée (crypto-shreddée) ou clé indisponible."""
    dek = _get_or_create_key_mem_readonly(entry["entity_id"])
    if dek is None:
        return None
    return crypto.decrypt_detail(entry["cipher"], dek)


def _get_or_create_key_mem_readonly(entity_id: str) -> bytes | None:
    wrapped = crypto._KEYRING.get(entity_id)
    return crypto.unwrap_key(wrapped) if wrapped else None


def forget(entity_id: str) -> int:
    """Crypto-shredding mémoire : détruit la DEK. Les détails de cette
    entité deviennent définitivement illisibles ; la chaîne reste valide.
    Renvoie le nombre d'entrées désormais illisibles."""
    _SHREDDED.add(entity_id)
    crypto._KEYRING.pop(entity_id, None)
    return sum(1 for e in _CHAIN if e["entity_id"] == entity_id)


# ============================================================
# API asynchrone (persistante si DB active, sinon mémoire)
# ============================================================

async def load_from_db() -> None:
    """Recharge la chaîne + le keyring persistés au démarrage."""
    if not db.is_enabled():
        return
    try:
        async with db.pool().acquire() as con:
            rows = await con.fetch(
                "SELECT ts, action, entity_type, entity_id, cipher, prev_hash, hash "
                "FROM audit_chain ORDER BY seq ASC"
            )
            keys = await con.fetch("SELECT entity_id, wrapped FROM audit_keys")
        _CHAIN.clear()
        for r in rows:
            _CHAIN.append(dict(r))
        crypto._KEYRING.clear()
        for k in keys:
            crypto._KEYRING[k["entity_id"]] = k["wrapped"]
    except Exception as e:
        _log.warning("rechargement audit impossible", extra={
            "event": "db_error", "op": "load_chain",
            "error": f"{type(e).__name__}: {e}"})


async def append_async(action: str, entity_type: str, entity_id: str,
                       detail: dict) -> dict:
    prev_hash = _CHAIN[-1]["hash"] if _CHAIN else _GENESIS

    if db.is_enabled():
        try:
            dek = await _get_or_create_key_db(entity_id)
        except Exception as e:
            _log.warning("keyring DB indisponible, repli memoire", extra={
                "event": "db_error", "op": "audit_key",
                "error": f"{type(e).__name__}: {e}"})
            dek = _get_or_create_key_mem(entity_id)
    else:
        dek = _get_or_create_key_mem(entity_id)

    cipher = crypto.encrypt_detail(detail, dek) if dek else "SHREDDED"
    entry = _build_entry(action, entity_type, entity_id, cipher, prev_hash)
    _CHAIN.append(entry)

    if db.is_enabled():
        try:
            async with db.pool().acquire() as con:
                await con.execute(
                    "INSERT INTO audit_chain "
                    "(ts, action, entity_type, entity_id, cipher, prev_hash, hash) "
                    "VALUES ($1, $2, $3, $4, $5, $6, $7)",
                    entry["ts"], entry["action"], entry["entity_type"],
                    entry["entity_id"], entry["cipher"], entry["prev_hash"],
                    entry["hash"],
                )
        except Exception as e:
            _log.warning("ecriture audit DB echouee", extra={
                "event": "db_error", "op": "append_chain",
                "error": f"{type(e).__name__}: {e}"})

    return entry


async def forget_async(entity_id: str) -> int:
    """Crypto-shredding persistant : supprime la DEK de `audit_keys`.
    La donnée devient irrécupérable ; la preuve d'existence (hash) demeure.
    Renvoie le nombre d'entrées d'audit concernées."""
    crypto._KEYRING.pop(entity_id, None)
    _SHREDDED.add(entity_id)
    if db.is_enabled():
        try:
            async with db.pool().acquire() as con:
                await con.execute(
                    "DELETE FROM audit_keys WHERE entity_id = $1", entity_id)
                row = await con.fetchrow(
                    "SELECT COUNT(*) AS n FROM audit_chain WHERE entity_id = $1",
                    entity_id)
                return int(row["n"]) if row else 0
        except Exception as e:
            _log.warning("crypto-shredding DB echoue", extra={
                "event": "db_error", "op": "forget",
                "error": f"{type(e).__name__}: {e}"})
    return sum(1 for e in _CHAIN if e["entity_id"] == entity_id)


async def verify_integrity_async() -> bool:
    """Vérifie la chaîne. En mode DB, relit la source de vérité."""
    if db.is_enabled():
        try:
            async with db.pool().acquire() as con:
                rows = await con.fetch(
                    "SELECT ts, action, entity_type, entity_id, cipher, prev_hash, hash "
                    "FROM audit_chain ORDER BY seq ASC"
                )
            prev = _GENESIS
            for r in rows:
                e = dict(r)
                expected = _seal({k: v for k, v in e.items() if k != "hash"}, prev)
                if e["hash"] != expected or e["prev_hash"] != prev:
                    return False
                prev = e["hash"]
            return True
        except Exception:
            pass  # repli sur le cache mémoire
    return verify_integrity()
