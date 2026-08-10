from __future__ import annotations
import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken

from .config import get_settings

settings = get_settings()

_pool = None
_ENABLED = bool(settings.database_url)


def _fernet() -> Fernet:
    """Clé de chiffrement au repos dérivée de la clé maître du vault."""
    raw = hashlib.sha256(bytes.fromhex(settings.vault_master_key)).digest()
    return Fernet(base64.urlsafe_b64encode(raw))


def encrypt(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str | None:
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except (InvalidToken, ValueError):
        return None


def is_enabled() -> bool:
    return _ENABLED and _pool is not None


async def init_db() -> None:
    """Ouvre le pool et crée les tables. Sans database_url : no-op
    (repli mémoire assuré par les modules vault/audit)."""
    global _pool
    if not settings.database_url:
        return
    try:
        import asyncpg
        _pool = await asyncpg.create_pool(
            dsn=settings.database_url, min_size=1, max_size=5,
            command_timeout=10,
        )
        async with _pool.acquire() as con:
            await con.execute("""
                CREATE TABLE IF NOT EXISTS vault (
                    token       TEXT PRIMARY KEY,
                    cipher      TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
                    expires_at  TIMESTAMPTZ NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_vault_expires ON vault (expires_at);

                CREATE TABLE IF NOT EXISTS audit_chain (
                    seq         BIGSERIAL PRIMARY KEY,
                    ts          DOUBLE PRECISION NOT NULL,
                    action      TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id   TEXT NOT NULL,
                    cipher      TEXT NOT NULL,
                    prev_hash   TEXT NOT NULL,
                    hash        TEXT NOT NULL
                );

                -- Keyring de la chaine d'audit : une cle de donnees (DEK)
                -- ALEATOIRE par entite, stockee ENVELOPPEE par la cle maitre.
                -- Supprimer une ligne = crypto-shredding (RGPD art. 17) :
                -- le detail devient illisible, la preuve d'existence reste.
                CREATE TABLE IF NOT EXISTS audit_keys (
                    entity_id  TEXT PRIMARY KEY,
                    wrapped    TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                );

                -- Metering par client et par jour : base de facturation,
                -- survit aux redemarrages.
                CREATE TABLE IF NOT EXISTS usage_counters (
                    client_id TEXT NOT NULL,
                    day       DATE NOT NULL,
                    prompts   BIGINT NOT NULL DEFAULT 0,
                    tokenized BIGINT NOT NULL DEFAULT 0,
                    blocked   BIGINT NOT NULL DEFAULT 0,
                    PRIMARY KEY (client_id, day)
                );

                CREATE TABLE IF NOT EXISTS provider_counters (
                    provider TEXT PRIMARY KEY,
                    requests BIGINT NOT NULL DEFAULT 0
                );

                -- Corpus confidentiel (L3), cloisonné par client.
                -- On ne stocke QUE des empreintes non réversibles :
                -- jamais le texte des documents.
                CREATE TABLE IF NOT EXISTS corpus_shingles (
                    client_id TEXT   NOT NULL,
                    shingle   BIGINT NOT NULL,
                    doc_id    TEXT   NOT NULL,
                    PRIMARY KEY (client_id, shingle)
                );

                CREATE TABLE IF NOT EXISTS corpus_chunks (
                    id        BIGSERIAL PRIMARY KEY,
                    client_id TEXT  NOT NULL,
                    doc_id    TEXT  NOT NULL,
                    vec       BYTEA NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_corpus_chunks_client
                    ON corpus_chunks (client_id);

                -- Index aveugle des personnes concernées : permet de
                -- retrouver les entrées d'un individu (RGPD art. 15/17)
                -- sans jamais stocker son identité en clair.
                ALTER TABLE audit_chain
                    ADD COLUMN IF NOT EXISTS subject_ref TEXT;
                CREATE INDEX IF NOT EXISTS idx_audit_subject
                    ON audit_chain (subject_ref);
            """)
    except Exception as e:
        # Connexion impossible : on reste en repli mémoire plutôt que crasher.
        _pool = None
        from . import logs
        logs.get_logger("db").warning(
            "persistance desactivee (repli memoire)",
            extra={"event": "db_error", "op": "init_db",
                   "error": f"{type(e).__name__}: {e}"})


async def close_db() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


def pool():
    return _pool