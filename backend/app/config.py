from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Base
    app_name: str = "SENTINEL"
    environment: str = "development"

    # --- Persistance (Neon Postgres) ---
    # Vide = repli mémoire (démo). Renseigné = persistance réelle.
    # Format asyncpg : postgresql://user:pass@host/db?sslmode=require
    database_url: str = ""
    vault_ttl_hours: int = 24          # durée de vie d'une correspondance token
    persist_audit: bool = True         # journal d'audit en base
    persist_vault: bool = True         # vault chiffré en base

    # Clés cryptographiques (32 octets hex chacune ; openssl rand -hex 32)
    vault_master_key: str = "0" * 64
    audit_hmac_key: str = "1" * 64

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


@lru_cache
def get_settings() -> Settings:
    return Settings()