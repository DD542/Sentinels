from __future__ import annotations
import pytest


@pytest.fixture(autouse=True)
def reset_vault():
    """Réinitialise le vault, la chaîne d'audit et le rate-limiter
    avant chaque test."""
    from app.vault import fpe
    from app.audit import chain, crypto
    from app import ratelimit
    from app.detection import l3_semantic
    fpe._REVERSE_MAP.clear()
    chain._CHAIN.clear()
    chain._SHREDDED.clear()
    crypto._KEYRING.clear()
    ratelimit._WINDOWS.clear()
    l3_semantic._SHINGLE_INDEX.clear()
    l3_semantic._DOC_CHUNKS.clear()
    yield
    fpe._REVERSE_MAP.clear()
    chain._CHAIN.clear()
    chain._SHREDDED.clear()
    crypto._KEYRING.clear()
    ratelimit._WINDOWS.clear()
    l3_semantic._SHINGLE_INDEX.clear()
    l3_semantic._DOC_CHUNKS.clear()
