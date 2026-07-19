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
    dashboard_token: str = ""
    # Format des logs : "json" (production, une ligne JSON par événement)
    # ou "text" (lisible, dev local).
    log_format: str = "json"
    # Détection
    l3_similarity_threshold: float = 0.86
    l3_simhash_max_distance: int = 3
    ambiguity_low: float = 0.35
    ambiguity_high: float = 0.65
    # Juge local
    ollama_base_url: str = "http://localhost:11434"
    ollama_judge_model: str = "qwen2.5:14b"
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
@lru_cache
def get_settings() -> Settings:
    return Settings()