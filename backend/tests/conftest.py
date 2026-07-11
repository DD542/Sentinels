from __future__ import annotations
import pytest


@pytest.fixture(autouse=True)
def reset_vault():
    """Réinitialise le vault et la chaîne d'audit avant chaque test."""
    from app.vault import fpe
    from app.audit import chain
    fpe._REVERSE_MAP.clear()
    chain._CHAIN.clear()
    yield
    fpe._REVERSE_MAP.clear()
    chain._CHAIN.clear()
