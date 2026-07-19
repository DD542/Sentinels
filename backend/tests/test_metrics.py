"""
Tests de l'endpoint /metrics (Prometheus). Les compteurs Prometheus sont
globaux au process : les tests mesurent des DELTAS (avant/apres), jamais
des valeurs absolues.
"""
from __future__ import annotations
import pytest
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY

from app.main import app
from app.config import get_settings
from app import auth

settings = get_settings()
IBAN = "FR7610107001011234567890129"


@pytest.fixture(autouse=True)
def reset_keys():
    auth._KEYS.clear()
    yield
    auth._KEYS.clear()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def api_key(client):
    resp = client.post("/admin/keys", json={
        "client_id": "test-company",
        "admin_token": settings.effective_admin_token,
    })
    return resp.json()["api_key"]


def _value(name: str, labels: dict | None = None) -> float:
    return REGISTRY.get_sample_value(name, labels or {}) or 0.0


class TestMetrics:
    def test_endpoint_returns_prometheus_format(self, client):
        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/plain")
        assert "sentinel_prompts_scanned_total" in resp.text
        assert "sentinel_scan_duration_seconds_bucket" in resp.text

    def test_scan_increments_counters(self, client, api_key):
        before_scanned = _value("sentinel_prompts_scanned_total")
        before_decisions = _value("sentinel_decisions_total", {
            "action": "TOKENIZE", "entity_type": "IBAN", "layer": "L1"})
        before_duration = _value("sentinel_scan_duration_seconds_count")

        client.post("/gateway/scan",
                    json={"text": f"virement vers {IBAN}"},
                    headers={"X-SENTINEL-Key": api_key})

        assert _value("sentinel_prompts_scanned_total") == before_scanned + 1
        assert _value("sentinel_decisions_total", {
            "action": "TOKENIZE", "entity_type": "IBAN",
            "layer": "L1"}) == before_decisions + 1
        assert _value("sentinel_scan_duration_seconds_count") > before_duration

    def test_rate_limited_counter(self, client, api_key, monkeypatch):
        monkeypatch.setattr(settings, "rate_limit_per_minute", 1)
        before = _value("sentinel_rate_limited_total")
        headers = {"X-SENTINEL-Key": api_key}
        client.post("/gateway/scan", json={"text": "ok"}, headers=headers)
        client.post("/gateway/scan", json={"text": "ok"}, headers=headers)
        assert _value("sentinel_rate_limited_total") == before + 1

    def test_audit_chain_gauge_tracks_entries(self, client, api_key):
        """La jauge lit l'etat reel de la chaine au moment du scrape."""
        client.post("/gateway/scan",
                    json={"text": f"virement vers {IBAN}"},
                    headers={"X-SENTINEL-Key": api_key})
        from app.audit import chain
        assert _value("sentinel_audit_chain_entries") == len(chain._CHAIN)
        assert len(chain._CHAIN) > 0

    def test_vault_tokens_gauge(self, client, api_key):
        client.post("/gateway/scan",
                    json={"text": f"virement vers {IBAN}"},
                    headers={"X-SENTINEL-Key": api_key})
        from app.vault import fpe
        assert _value("sentinel_vault_tokens") == len(fpe._REVERSE_MAP)
        assert len(fpe._REVERSE_MAP) > 0
