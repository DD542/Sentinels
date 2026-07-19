from __future__ import annotations
import hashlib
import hmac
import json
import time

from ..config import get_settings
from .. import db
from .. import logs

settings = get_settings()
_log = logs.get_logger("audit")
_HMAC_KEY = bytes.fromhex(settings.audit_hmac_key)
_GENESIS = "0" * 64

# Cache mémoire (toujours actif ; source de vérité si pas de DB).
_CHAIN: list[dict] = []


def _entity_key(entity_id: str) -> bytes:
    """Clé dérivée par entité (base du crypto-shredding)."""
    return hmac.new(_HMAC_KEY, entity_id.encode(), hashlib.sha256).digest()


def _xor_encrypt(detail: dict, entity_id: str) -> str:
    key = _entity_key(entity_id)
    blob = json.dumps(detail).encode()
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(blob)).hex()


def _seal(payload: dict, prev_hash: str) -> str:
    material = json.dumps(payload, sort_keys=True) + prev_hash
    return hmac.new(_HMAC_KEY, material.encode(), hashlib.sha256).hexdigest()


def _build_entry(action, entity_type, entity_id, detail, prev_hash) -> dict:
    entry = {
        "ts": time.time(),
        "action": action,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "cipher": _xor_encrypt(detail, entity_id),
        "prev_hash": prev_hash,
    }
    entry["hash"] = _seal(entry, prev_hash)
    return entry


# ============================================================
# API synchrone (repli mémoire, conservée pour compat)
# ============================================================

def append(action: str, entity_type: str, entity_id: str, detail: dict) -> dict:
    prev_hash = _CHAIN[-1]["hash"] if _CHAIN else _GENESIS
    entry = _build_entry(action, entity_type, entity_id, detail, prev_hash)
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


# ============================================================
# API asynchrone (persistante si DB active, sinon mémoire)
# ============================================================

async def load_from_db() -> None:
    """Recharge la chaîne persistée au démarrage (reconstruit le cache)."""
    if not db.is_enabled():
        return
    try:
        async with db.pool().acquire() as con:
            rows = await con.fetch(
                "SELECT ts, action, entity_type, entity_id, cipher, prev_hash, hash "
                "FROM audit_chain ORDER BY seq ASC"
            )
        _CHAIN.clear()
        for r in rows:
            _CHAIN.append(dict(r))
    except Exception as e:
        _log.warning("rechargement audit impossible", extra={
            "event": "db_error", "op": "load_chain",
            "error": f"{type(e).__name__}: {e}"})


async def append_async(action: str, entity_type: str, entity_id: str,
                       detail: dict) -> dict:
    prev_hash = _CHAIN[-1]["hash"] if _CHAIN else _GENESIS
    entry = _build_entry(action, entity_type, entity_id, detail, prev_hash)
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