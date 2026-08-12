from __future__ import annotations
import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import get_settings

settings = get_settings()

_pool = None
_ENABLED = bool(settings.database_url)


# ============================================================
# Chiffrement du vault : une clé PAR CLIENT
# ============================================================
#
# Le vault était chiffré avec une clé unique. Le cloisonnement entre
# organisations n'existait alors qu'au niveau logique — une clause SQL.
# Or c'est précisément une erreur de cloisonnement logique qui a déjà
# livré à un client les données d'un autre : une requête sans filtre
# rendait des lignes lisibles.
#
# Avec une clé par client, la même erreur ne rend plus rien : la ligne
# revient, mais elle ne se déchiffre pas. Le contrôle passe d'une
# convention de codage à une propriété cryptographique.
#
# Deux origines possibles pour cette clé :
#
#   * **dérivée** de la clé maître (défaut) — défense en profondeur
#     contre les erreurs de cloisonnement. L'exploitant de SENTINEL
#     conserve la capacité de déchiffrer ;
#   * **fournie par le client** (`vault_client_keys`) — le client garde
#     sa clé. L'exploitant ne peut alors PAS lire son vault, même avec
#     un accès complet à la base. C'est la réponse à la question que
#     pose tout service achats : « vos équipes peuvent-elles lire nos
#     données ? »

_HKDF_SALT = b"sentinel-vault-partition-v1"
_cle_par_client: dict[str, Fernet] = {}


def _derive(secret: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=_HKDF_SALT, info=info).derive(secret)


def _fernet() -> Fernet:
    """Clé historique, dérivée de la seule clé maître.

    Conservée pour relire les lignes écrites avant le cloisonnement.
    Comme le vault expire en `VAULT_TTL_HOURS` (24 h par défaut), ce
    repli cesse naturellement d'être sollicité après une journée."""
    raw = hashlib.sha256(bytes.fromhex(settings.vault_master_key)).digest()
    return Fernet(base64.urlsafe_b64encode(raw))


def _client_fernet(client_id: str) -> Fernet:
    cache = _cle_par_client.get(client_id)
    if cache is not None:
        return cache

    fournie = settings.vault_key_for(client_id)
    if fournie:
        # Clé du client : jamais dérivée de la nôtre, sinon la promesse
        # « vous seul pouvez déchiffrer » serait fausse.
        brut = _derive(bytes.fromhex(fournie), b"client-supplied")
    else:
        brut = _derive(bytes.fromhex(settings.vault_master_key),
                       client_id.encode())

    cle = Fernet(base64.urlsafe_b64encode(brut))
    _cle_par_client[client_id] = cle
    return cle


def _reset_key_cache() -> None:
    """Utilisé par les tests et après un changement de configuration."""
    _cle_par_client.clear()


def encrypt(plaintext: str, client_id: str) -> str:
    return _client_fernet(client_id).encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str, client_id: str) -> str | None:
    """Déchiffre avec la clé du client.

    Le repli sur la clé historique ne relit que les lignes antérieures au
    cloisonnement. Il ne crée aucun passage entre clients : une ligne
    chiffrée pour le client A avec SA clé reste illisible pour B."""
    donnee = ciphertext.encode()
    try:
        return _client_fernet(client_id).decrypt(donnee).decode()
    except (InvalidToken, ValueError):
        pass
    if settings.vault_key_for(client_id):
        # Client à clé propre : aucun repli possible ni souhaitable.
        return None
    try:
        return _fernet().decrypt(donnee).decode()
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

                -- Cloisonnement du vault : sans lui, la reponse d'un
                -- fournisseur destinee au client B se voyait restaurer
                -- avec les VRAIES valeurs du client A.
                ALTER TABLE vault
                    ADD COLUMN IF NOT EXISTS client_id TEXT NOT NULL
                    DEFAULT '_global';
                ALTER TABLE vault DROP CONSTRAINT IF EXISTS vault_pkey;
                CREATE UNIQUE INDEX IF NOT EXISTS idx_vault_client_token
                    ON vault (client_id, token);

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

                -- Politique de detection par client : exceptions,
                -- seuils et actions. Cloisonnee comme le corpus.
                CREATE TABLE IF NOT EXISTS client_policies (
                    client_id  TEXT PRIMARY KEY,
                    policy     TEXT NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                );

                -- Point de controle de verification : jusqu'ou la chaine
                -- a deja ete verifiee. Permet de ne revalider que les
                -- entrees ajoutees depuis, au lieu de tout relire a
                -- chaque fois.
                CREATE TABLE IF NOT EXISTS audit_checkpoint (
                    id          INT PRIMARY KEY,
                    seq         BIGINT NOT NULL,
                    hash        TEXT NOT NULL,
                    verified_at DOUBLE PRECISION NOT NULL
                );

                -- Registre de révocation des sessions du dashboard :
                -- sans lui, un cookie volé resterait valable jusqu'à
                -- son expiration.
                CREATE TABLE IF NOT EXISTS session_revocations (
                    scope      TEXT NOT NULL,   -- jti | subject | global
                    value      TEXT NOT NULL,
                    revoked_at DOUBLE PRECISION NOT NULL,
                    PRIMARY KEY (scope, value)
                );

                -- Index aveugle des personnes concernées : permet de
                -- retrouver les entrées d'un individu (RGPD art. 15/17)
                -- sans jamais stocker son identité en clair.
                ALTER TABLE audit_chain
                    ADD COLUMN IF NOT EXISTS subject_ref TEXT;

                -- Cloisonnement par client : une chaine de hachage par
                -- tenant. NULL = chaine de l'exploitant (et entrees
                -- anterieures au cloisonnement).
                ALTER TABLE audit_chain
                    ADD COLUMN IF NOT EXISTS tenant TEXT;
                CREATE INDEX IF NOT EXISTS idx_audit_tenant
                    ON audit_chain (tenant, seq);

                CREATE TABLE IF NOT EXISTS audit_checkpoints (
                    tenant      TEXT PRIMARY KEY,
                    seq         BIGINT NOT NULL,
                    hash        TEXT NOT NULL,
                    verified_at DOUBLE PRECISION NOT NULL
                );
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