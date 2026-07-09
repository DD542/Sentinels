from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Base
    app_name: str = "SENTINEL"
    environment: str = "development"

    # Base de données
    database_url: str = "postgresql+asyncpg://user:pass@localhost:5432/sentinel"

    # Clés cryptographiques (32 octets hex chacune, à générer en prod)
    # openssl rand -hex 32
    vault_master_key: str = "0" * 64          # clé maître du vault de tokenisation
    audit_hmac_key: str = "1" * 64            # clé HMAC du journal d'audit

    # Détection
    l3_similarity_threshold: float = 0.86     # seuil pgvector fuite IP
    l3_simhash_max_distance: int = 3          # distance Hamming SimHash
    ambiguity_low: float = 0.35               # zone grise -> juge L4
    ambiguity_high: float = 0.65

    # Juge local
    ollama_base_url: str = "http://localhost:11434"
    ollama_judge_model: str = "qwen2.5:14b"

    # Fournisseurs IA amont
    anthropic_base: str = "https://api.anthropic.com"
    openai_base: str = "https://api.openai.com"
    groq_base: str = "https://api.groq.com"


@lru_cache
def get_settings() -> Settings:
    return Settings()