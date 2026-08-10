from __future__ import annotations
import hashlib
import hmac
import json
import time

from ..config import get_settings
from .. import db
from .. import logs
from . import crypto
from . import subjects

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
    Si la ligne a été supprimée (oubli), renvoie None.

    La DEK enveloppée est aussi mise en cache dans le keyring mémoire :
    sans ça, une entrée écrite ne serait relisible qu'après redémarrage,
    et une donnée simplement non chargée serait indiscernable d'une
    donnée effacée."""
    async with db.pool().acquire() as con:
        row = await con.fetchrow(
            "SELECT wrapped FROM audit_keys WHERE entity_id = $1", entity_id)
        if row is not None:
            crypto._KEYRING[entity_id] = row["wrapped"]
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
            if row is None:
                return None
            crypto._KEYRING[entity_id] = row["wrapped"]
            return crypto.unwrap_key(row["wrapped"])
        crypto._KEYRING[entity_id] = wrapped
        return dek


def _build_entry(action, entity_type, entity_id, cipher, prev_hash,
                 subject_ref: str | None = None) -> dict:
    entry = {
        "ts": time.time(),
        "action": action,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "cipher": cipher,
        "prev_hash": prev_hash,
    }
    # Champ ajouté seulement s'il existe : les entrées antérieures à
    # l'index aveugle ont été scellées sans lui, leur hash doit rester
    # vérifiable à l'identique.
    if subject_ref:
        entry["subject_ref"] = subject_ref
    entry["hash"] = _seal(entry, prev_hash)
    return entry


def _row_to_entry(row) -> dict:
    """Ligne SQL -> entrée. `subject_ref` NULL est retiré : la colonne
    existe pour toutes les lignes, mais les anciennes ont été scellées
    sans ce champ."""
    entry = dict(row)
    if entry.get("subject_ref") is None:
        entry.pop("subject_ref", None)
    return entry


def _key_id(entry: dict) -> str:
    """Identifiant de la clé de chiffrement d'une entrée : la personne
    concernée quand elle est connue (l'oubli est alors chirurgical),
    sinon l'entité technique."""
    return entry.get("subject_ref") or entry["entity_id"]


# ============================================================
# API synchrone (repli mémoire, conservée pour compat)
# ============================================================

def append(action: str, entity_type: str, entity_id: str, detail: dict,
           subject: str | None = None) -> dict:
    prev_hash = _CHAIN[-1]["hash"] if _CHAIN else _GENESIS
    ref = subjects.subject_ref(subject)
    dek = _get_or_create_key_mem(ref or entity_id)
    # dek None (entité oubliée) : on scelle un marqueur non déchiffrable.
    cipher = crypto.encrypt_detail(detail, dek) if dek else "SHREDDED"
    entry = _build_entry(action, entity_type, entity_id, cipher, prev_hash, ref)
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
    None = personne oubliée (crypto-shreddée) ou clé indisponible."""
    dek = _get_or_create_key_mem_readonly(_key_id(entry))
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
    return sum(1 for e in _CHAIN if _key_id(e) == entity_id)


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
                "SELECT ts, action, entity_type, entity_id, cipher, prev_hash, "
                "hash, subject_ref FROM audit_chain ORDER BY seq ASC"
            )
            keys = await con.fetch("SELECT entity_id, wrapped FROM audit_keys")
        _CHAIN.clear()
        for r in rows:
            _CHAIN.append(_row_to_entry(r))
        crypto._KEYRING.clear()
        for k in keys:
            crypto._KEYRING[k["entity_id"]] = k["wrapped"]
    except Exception as e:
        _log.warning("rechargement audit impossible", extra={
            "event": "db_error", "op": "load_chain",
            "error": f"{type(e).__name__}: {e}"})


async def append_async(action: str, entity_type: str, entity_id: str,
                       detail: dict, subject: str | None = None) -> dict:
    """`subject` : la valeur identifiant la personne concernée (nom, IBAN…).
    Elle n'est jamais stockée : seule sa référence aveugle l'est, et elle
    sert de clé de chiffrement — l'oubli d'une personne ne touche donc
    qu'elle."""
    prev_hash = _CHAIN[-1]["hash"] if _CHAIN else _GENESIS
    ref = subjects.subject_ref(subject)
    key_id = ref or entity_id

    if db.is_enabled():
        try:
            dek = await _get_or_create_key_db(key_id)
        except Exception as e:
            _log.warning("keyring DB indisponible, repli memoire", extra={
                "event": "db_error", "op": "audit_key",
                "error": f"{type(e).__name__}: {e}"})
            dek = _get_or_create_key_mem(key_id)
    else:
        dek = _get_or_create_key_mem(key_id)

    cipher = crypto.encrypt_detail(detail, dek) if dek else "SHREDDED"
    entry = _build_entry(action, entity_type, entity_id, cipher, prev_hash, ref)
    _CHAIN.append(entry)

    if db.is_enabled():
        try:
            async with db.pool().acquire() as con:
                await con.execute(
                    "INSERT INTO audit_chain "
                    "(ts, action, entity_type, entity_id, cipher, prev_hash, "
                    "hash, subject_ref) "
                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                    entry["ts"], entry["action"], entry["entity_type"],
                    entry["entity_id"], entry["cipher"], entry["prev_hash"],
                    entry["hash"], ref,
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


async def subject_summary(value: str) -> dict:
    """Droit d'accès (RGPD art. 15) : ce que le journal contient sur une
    personne. On renvoie des **métadonnées** (nombre d'entrées, types de
    données, période, actions) — jamais les valeurs, qui restent
    chiffrées. La valeur fournie n'est ni stockée ni journalisée."""
    ref = subjects.subject_ref(value)
    if ref is None:
        return {"found": False, "entries": 0}

    if db.is_enabled():
        try:
            async with db.pool().acquire() as con:
                rows = await con.fetch(
                    "SELECT action, entity_type, MIN(ts) AS first_ts, "
                    "MAX(ts) AS last_ts, COUNT(*) AS n FROM audit_chain "
                    "WHERE subject_ref = $1 GROUP BY action, entity_type", ref)
                key = await con.fetchrow(
                    "SELECT 1 FROM audit_keys WHERE entity_id = $1", ref)
            total = sum(int(r["n"]) for r in rows)
            return {
                "found": total > 0,
                "entries": total,
                "erased": total > 0 and key is None,
                "breakdown": [{"action": r["action"],
                               "entity_type": r["entity_type"],
                               "count": int(r["n"])} for r in rows],
                "first_seen": min((r["first_ts"] for r in rows), default=None),
                "last_seen": max((r["last_ts"] for r in rows), default=None),
            }
        except Exception as e:
            _log.warning("resume par personne echoue", extra={
                "event": "db_error", "op": "subject_summary",
                "error": f"{type(e).__name__}: {e}"})

    matching = [e for e in _CHAIN if e.get("subject_ref") == ref]
    return {
        "found": bool(matching),
        "entries": len(matching),
        "erased": bool(matching) and ref not in crypto._KEYRING,
        "breakdown": [{"action": e["action"],
                       "entity_type": e["entity_type"], "count": 1}
                      for e in matching],
        "first_seen": min((e["ts"] for e in matching), default=None),
        "last_seen": max((e["ts"] for e in matching), default=None),
    }


async def forget_subject(value: str) -> int:
    """Droit à l'effacement (RGPD art. 17) visant **une personne**.

    Détruit la clé de la personne : toutes ses entrées deviennent
    illisibles, et **uniquement les siennes** — c'est tout l'intérêt
    d'avoir indexé par personne plutôt que par entité technique.
    Renvoie le nombre d'entrées concernées."""
    ref = subjects.subject_ref(value)
    if ref is None:
        return 0

    crypto._KEYRING.pop(ref, None)
    _SHREDDED.add(ref)

    if db.is_enabled():
        try:
            async with db.pool().acquire() as con:
                await con.execute(
                    "DELETE FROM audit_keys WHERE entity_id = $1", ref)
                row = await con.fetchrow(
                    "SELECT COUNT(*) AS n FROM audit_chain "
                    "WHERE subject_ref = $1", ref)
            return int(row["n"]) if row else 0
        except Exception as e:
            _log.warning("effacement par personne echoue", extra={
                "event": "db_error", "op": "forget_subject",
                "error": f"{type(e).__name__}: {e}"})
    return sum(1 for e in _CHAIN if e.get("subject_ref") == ref)


async def purge_expired_keys(retention_days: int) -> int:
    """Applique la durée de conservation du journal, par crypto-shredding.

    Les entrées d'audit ne sont **jamais supprimées** : la chaîne de
    hachage doit rester vérifiable de bout en bout (AI Act art. 26(6)),
    et une suppression casserait le chaînage. C'est leur clé de
    déchiffrement qui est détruite au-delà de la rétention : le détail
    devient illisible (RGPD art. 5(1)(e), limitation de conservation)
    alors que la preuve qu'un traitement a eu lieu demeure.

    Une entité est expirée quand sa **dernière** entrée dépasse la durée.
    Renvoie le nombre d'entités dont la clé a été détruite."""
    if retention_days <= 0 or not db.is_enabled():
        return 0
    cutoff = time.time() - retention_days * 86400
    try:
        async with db.pool().acquire() as con:
            rows = await con.fetch(
                "DELETE FROM audit_keys WHERE entity_id IN ("
                "  SELECT entity_id FROM audit_chain GROUP BY entity_id"
                "  HAVING MAX(ts) < $1"
                ") RETURNING entity_id", cutoff)
    except Exception as e:
        _log.warning("purge des cles d'audit echouee", extra={
            "event": "db_error", "op": "purge_keys",
            "error": f"{type(e).__name__}: {e}"})
        return 0

    # On vide le cache, sans marquer l'entité comme oubliée : les
    # identifiants d'entité sont réutilisés d'un prompt à l'autre, et une
    # donnée future n'a pas à être privée de clé. Les anciennes entrées
    # restent illisibles, leur DEK ayant disparu.
    for r in rows:
        crypto._KEYRING.pop(r["entity_id"], None)
    if rows:
        _log.info("cles d'audit expirees detruites", extra={
            "event": "audit_key_purge", "entities": len(rows),
            "retention_days": retention_days})
    return len(rows)


async def verify_integrity_async() -> bool:
    """Vérifie la chaîne. En mode DB, relit la source de vérité."""
    if db.is_enabled():
        try:
            async with db.pool().acquire() as con:
                rows = await con.fetch(
                    "SELECT ts, action, entity_type, entity_id, cipher, prev_hash, "
                    "hash, subject_ref FROM audit_chain ORDER BY seq ASC"
                )
            prev = _GENESIS
            for r in rows:
                e = _row_to_entry(r)
                expected = _seal({k: v for k, v in e.items() if k != "hash"}, prev)
                if e["hash"] != expected or e["prev_hash"] != prev:
                    return False
                prev = e["hash"]
            return True
        except Exception:
            pass  # repli sur le cache mémoire
    return verify_integrity()
