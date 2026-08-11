from functools import lru_cache
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator
# Chemin ABSOLU du .env : backend/.env, quel que soit le dossier de lancement.
# config.py est dans backend/app/, donc .env est un niveau au-dessus.
_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=str(_ENV_PATH), extra="ignore")
    # Base
    app_name: str = "SENTINEL"
    environment: str = "development"
    # --- Persistance (Neon Postgres) ---
    database_url: str = ""
    vault_ttl_hours: int = 24
    # Conservation du journal d'audit, en jours. 0 = illimité.
    # Au-delà, les ENTRÉES SONT CONSERVÉES (la chaîne doit rester
    # vérifiable) mais leur clé de déchiffrement est détruite : la preuve
    # demeure, la donnée personnelle devient illisible.
    audit_retention_days: int = 0
    # Période entre deux passes de maintenance (purges). 0 = désactivé.
    purge_interval_minutes: int = 60
    # Période entre deux vérifications COMPLÈTES du journal, en heures.
    # L'incrémentale (à chaque passe) ne voit pas une altération
    # ANTÉRIEURE au point de contrôle : seule la complète la détecte.
    # 0 = jamais (uniquement au démarrage et à la demande).
    audit_full_verify_hours: int = 24
    # Streaming : "natif" relaie les fragments du fournisseur au fil de
    # l'eau (latence minimale, désanonymisation incrémentale). False =
    # réponse complète puis découpage simulé — restauration maximale
    # (récupération floue comprise) mais l'utilisateur attend la fin.
    stream_native: bool = True
    persist_audit: bool = True
    persist_vault: bool = True
    # Clés cryptographiques (32 octets hex chacune ; openssl rand -hex 32)
    vault_master_key: str = "0" * 64
    audit_hmac_key: str = "1" * 64
    # Token d'administration (création de clés clients). Distinct des clés
    # cryptographiques : une clé HMAC sert à signer, jamais à s'authentifier.
    # Vide = repli sur audit_hmac_key (compatibilité installations existantes).
    admin_token: str = ""
    # Rate-limiting par client (fenêtre glissante 60 s). 0 = désactivé.
    rate_limit_per_minute: int = 120
    # Token du dashboard (API stats + WebSocket temps réel).
    # Vide = accès libre (dev/démo) ; défini = obligatoire.
    # Reste utilisable en accès de secours quand le SSO est actif.
    dashboard_token: str = ""

    # --- SSO d'entreprise (OpenID Connect) ---
    # Actif dès qu'un émetteur et un identifiant client sont fournis.
    oidc_issuer: str = ""            # ex. https://login.microsoftonline.com/<tenant>/v2.0
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    # URL de retour déclarée chez le fournisseur d'identité.
    oidc_redirect_uri: str = "http://localhost:8000/auth/callback"
    oidc_scopes: str = "openid email profile"
    # Restriction d'accès : domaine de messagerie et/ou groupes.
    # Sans restriction, tout compte connu du fournisseur entrerait.
    oidc_allowed_domains: str = ""   # ex. "monentreprise.fr,filiale.fr"
    oidc_allowed_groups: str = ""    # ex. "rssi,dpo" (revendication `groups`)
    # Correspondance groupes -> rôles de la console. Un compte
    # autorisé mais sans groupe reconnu reçoit le rôle le plus
    # faible : une configuration incomplète ne doit pas donner
    # les droits d'administration.
    oidc_admin_groups: str = ""      # ex. "rssi,it-admin"
    oidc_auditor_groups: str = ""    # ex. "dpo,audit-interne"
    oidc_viewer_groups: str = ""     # ex. "soc,analystes"
    # Durée d'une session dashboard, en heures.
    session_ttl_hours: int = 8
    # Cookie `Secure` : à laisser vrai partout sauf en HTTP local.
    session_cookie_secure: bool = True
    # Format des logs : "json" (production, une ligne JSON par événement)
    # ou "text" (lisible, dev local).
    log_format: str = "json"
    # Mode strict (production) : refuse de DÉMARRER si la posture est
    # incomplète (persistance absente, clés crypto par défaut, tokens
    # admin/dashboard non définis). Fail-closed plutôt que fail-open.
    strict_mode: bool = False
    # Détection
    # Nombre de fils d'exécution pour la détection (travail CPU :
    # spaCy, Presidio). 0 = nombre de cœurs. Au-delà, les fils se
    # disputent le GIL et le débit S'EFFONDRE au lieu de plafonner :
    # mesuré 70 req/s à 8 requêtes simultanées, 12 req/s à 16.
    detection_workers: int = 0
    l3_similarity_threshold: float = 0.86
    l3_simhash_max_distance: int = 3
    ambiguity_low: float = 0.35
    ambiguity_high: float = 0.65
    # Juge local
    ollama_base_url: str = "http://localhost:11434"
    ollama_judge_model: str = "qwen2.5:14b"
    # Une inference coute 5 a 25 s selon le modele et la longueur : bien
    # au-dela des 13 ms du reste du pipeline. Au-dela de ce delai, on
    # abandonne le rattrapage plutot que de faire attendre l'employe.
    l4_timeout_seconds: float = 30.0
    # Fournisseurs IA amont
    anthropic_base: str = "https://api.anthropic.com"
    openai_base: str = "https://api.openai.com"
    groq_base: str = "https://api.groq.com"
    mistral_base: str = "https://api.mistral.ai"
    # Clés fournisseurs — stockées cote serveur uniquement (jamais envoyees
    # par le client). Utilisees par l'endpoint /v1/chat/completions.
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    groq_api_key: str = ""
    mistral_api_key: str = ""
    @field_validator("vault_master_key", "audit_hmac_key", "database_url",
                     "admin_token", "dashboard_token", mode="before")
    @classmethod
    def _strip_whitespace(cls, v):
        if isinstance(v, str):
            return v.strip().strip("\r\n")
        return v

    @property
    def effective_admin_token(self) -> str:
        return self.admin_token or self.audit_hmac_key

    @property
    def sso_enabled(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_client_id)
@lru_cache
def get_settings() -> Settings:
    return Settings()