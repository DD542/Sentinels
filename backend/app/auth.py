from __future__ import annotations
import hashlib
import hmac
import secrets
from datetime import datetime, timezone

from fastapi import Header, HTTPException
from .config import get_settings
from . import db

settings = get_settings()

# Cache mémoire : hash_de_cle -> {client_id, active, created_at}
# Toujours actif ; source de verite si pas de DB.
_KEYS: dict[str, dict] = {}


def _hash_key(raw_key: str) -> str:
    """Hache une cle API avec la cle maitre (HMAC-SHA256).
    On ne stocke JAMAIS la cle en clair, seulement son empreinte."""
    return hmac.new(
        bytes.fromhex(settings.vault_master_key),
        raw_key.encode(), hashlib.sha256,
    ).hexdigest()


def generate_key(client_id: str) -> str:
    """Cree une nouvelle cle API pour un client (version memoire).
    Retourne la cle EN CLAIR une seule fois."""
    raw_key = "sntl_" + secrets.token_urlsafe(32)
    key_hash = _hash_key(raw_key)
    _KEYS[key_hash] = {
        "client_id": client_id,
        "active": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    return raw_key


async def generate_key_async(client_id: str) -> str:
    """Cree une cle API pour un client, persistee si DB active."""
    raw_key = "sntl_" + secrets.token_urlsafe(32)
    key_hash = _hash_key(raw_key)
    now = datetime.now(timezone.utc)
    _KEYS[key_hash] = {"client_id": client_id, "active": True,
                       "created_at": now.isoformat()}

    if db.is_enabled():
        try:
            async with db.pool().acquire() as con:
                await con.execute(
                    "INSERT INTO api_keys (key_hash, client_id, active, created_at) "
                    "VALUES ($1, $2, TRUE, $3) "
                    "ON CONFLICT (key_hash) DO NOTHING",
                    key_hash, client_id, now,
                )
        except Exception as e:
            print(f"[SENTINEL] Ecriture cle DB echouee : {type(e).__name__}: {e}")

    return raw_key


async def _lookup_key(key_hash: str) -> dict | None:
    if key_hash in _KEYS:
        rec = _KEYS[key_hash]
        return rec if rec["active"] else None
    if db.is_enabled():
        try:
            async with db.pool().acquire() as con:
                row = await con.fetchrow(
                    "SELECT client_id, active FROM api_keys WHERE key_hash = $1",
                    key_hash,
                )
            if row and row["active"]:
                return {"client_id": row["client_id"], "active": True}
        except Exception:
            pass
    return None


async def verify_key(x_sentinel_key: str | None = Header(default=None)) -> str:
    """Dependance FastAPI : verifie la cle et retourne le client_id.
    Rejette en 401 si absente, invalide ou revoquee.

    Bootstrap : si AUCUNE cle n'existe encore (et pas de DB), on laisse
    passer pour ne pas te verrouiller dehors au premier lancement. Des
    qu'une cle est creee, l'authentification devient stricte."""
    if not _KEYS and not db.is_enabled():
        return "bootstrap"

    if not x_sentinel_key:
        raise HTTPException(status_code=401,
                            detail="Cle SENTINEL manquante (header X-SENTINEL-Key)")

    key_hash = _hash_key(x_sentinel_key)
    record = await _lookup_key(key_hash)
    if record is None:
        raise HTTPException(status_code=401, detail="Cle SENTINEL invalide ou revoquee")

    return record["client_id"]


async def verify_bearer_key(authorization: str | None = Header(default=None)) -> str:
    """Dependance FastAPI pour les endpoints compatibles OpenAI : lit la cle
    depuis 'Authorization: Bearer <cle>' au lieu de X-SENTINEL-Key. Meme
    logique de verification que verify_key, juste un header different
    (c'est le seul format qu'un client OpenAI standard sait envoyer)."""
    if not _KEYS and not db.is_enabled():
        return "bootstrap"

    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401,
                            detail="Cle manquante (header Authorization: Bearer <cle>)")

    raw_key = authorization[7:].strip()
    key_hash = _hash_key(raw_key)
    record = await _lookup_key(key_hash)
    if record is None:
        raise HTTPException(status_code=401, detail="Cle invalide ou revoquee")

    return record["client_id"]


async def revoke_key(raw_key: str) -> bool:
    """Revoque une cle (desactive). Utile pour un futur endpoint admin."""
    key_hash = _hash_key(raw_key)
    revoked = False
    if key_hash in _KEYS:
        _KEYS[key_hash]["active"] = False
        revoked = True
    if db.is_enabled():
        try:
            async with db.pool().acquire() as con:
                await con.execute(
                    "UPDATE api_keys SET active = FALSE WHERE key_hash = $1",
                    key_hash,
                )
            revoked = True
        except Exception:
            pass
    return revoked


async def load_keys_from_db() -> None:
    """Cree la table api_keys et recharge les cles actives au demarrage."""
    if not db.is_enabled():
        return
    try:
        async with db.pool().acquire() as con:
            await con.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    key_hash   TEXT PRIMARY KEY,
                    client_id  TEXT NOT NULL,
                    active     BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                );
            """)
            rows = await con.fetch(
                "SELECT key_hash, client_id, active FROM api_keys WHERE active = TRUE"
            )
        for r in rows:
            _KEYS[r["key_hash"]] = {"client_id": r["client_id"],
                                    "active": r["active"], "created_at": None}
    except Exception as e:
        print(f"[SENTINEL] Chargement cles impossible : {type(e).__name__}: {e}")