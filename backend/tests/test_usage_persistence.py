"""
Tests de la persistance du metering : reconstruction des compteurs
depuis les agregats de la chaine d'audit (fonction pure, sans DB),
no-op propre sans persistance, et champ persistent de /admin/usage.
"""
from __future__ import annotations
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import get_settings
from app import auth
from app import events

settings = get_settings()


@pytest.fixture(autouse=True)
def reset_state():
    auth._KEYS.clear()
    events.reset()
    yield
    auth._KEYS.clear()
    events.reset()


@pytest.fixture
def client():
    return TestClient(app)


class TestChainAggregateRebuild:
    def test_decisions_rebuilt(self):
        """Les agregats de la chaine reconstruisent les memes compteurs
        que publish() : TOKENIZE, BLOCK, BLOCK_REQUEST."""
        events._apply_chain_aggregate("TOKENIZE", "IBAN", 5)
        events._apply_chain_aggregate("TOKENIZE", "PERSON", 3)
        events._apply_chain_aggregate("BLOCK", "SECRET", 2)
        events._apply_chain_aggregate("BLOCK_REQUEST", "IP_LEAK", 1)

        stats = events.snapshot()["stats"]
        assert stats["entities_tokenized"] == 8
        assert stats["by_type"] == {"IBAN": 5, "PERSON": 3, "SECRET": 2}
        assert stats["secrets_blocked"] == 2
        assert stats["requests_blocked"] == 1
        assert stats["ip_leaks_blocked"] == 1

    def test_non_decision_actions_ignored(self):
        """CORPUS_INGEST, KEY_REVOKED, EVASION_ATTEMPT ne comptent pas."""
        for action in ("CORPUS_INGEST", "KEY_REVOKED", "EVASION_ATTEMPT"):
            events._apply_chain_aggregate(action, "X", 10)
        stats = events.snapshot()["stats"]
        assert stats["entities_tokenized"] == 0
        assert stats["secrets_blocked"] == 0
        assert stats["by_type"] == {}


class TestWithoutPersistence:
    @pytest.mark.asyncio
    async def test_load_stats_noop_without_db(self):
        await events.load_stats_from_db()
        assert events.snapshot()["stats"]["prompts_scanned"] == 0

    def test_usage_reports_not_persistent(self, client):
        resp = client.get("/admin/usage", headers={
            "X-Admin-Token": settings.effective_admin_token})
        assert resp.status_code == 200
        assert resp.json()["persistent"] is False
