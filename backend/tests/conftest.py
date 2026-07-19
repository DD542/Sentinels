from __future__ import annotations
import pytest


@pytest.fixture(autouse=True)
def reset_vault():
    """Réinitialise le vault, la chaîne d'audit et le rate-limiter
    avant chaque test."""
    from app.vault import fpe
    from app.audit import chain
    from app import ratelimit
    fpe._REVERSE_MAP.clear()
    chain._CHAIN.clear()
    ratelimit._WINDOWS.clear()
    yield
    fpe._REVERSE_MAP.clear()
    chain._CHAIN.clear()
    ratelimit._WINDOWS.clear()
