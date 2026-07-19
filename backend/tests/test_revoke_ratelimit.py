"""
Tests de durcissement production : revocation de cles par client
(/admin/keys/revoke) et rate-limiting par client (fenetre glissante 60 s).
"""
from __future__ import annotations
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import get_settings
from app import auth

settings = get_settings()


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
    assert resp.status_code == 200
    return resp.json()["api_key"]


def _revoke(client, client_id, token):
    return client.post("/admin/keys/revoke",
                       json={"client_id": client_id, "admin_token": token})


class TestRevocation:
    def test_revoked_key_rejected(self, client, api_key):
        """Une cle fonctionne, est revoquee, puis est rejetee en 401."""
        headers = {"X-SENTINEL-Key": api_key}
        assert client.post("/gateway/scan", json={"text": "bonjour"},
                           headers=headers).status_code == 200

        resp = _revoke(client, "test-company", settings.effective_admin_token)
        assert resp.status_code == 200
        assert resp.json()["keys_revoked"] == 1
        assert "audit_hash" in resp.json()

        assert client.post("/gateway/scan", json={"text": "bonjour"},
                           headers=headers).status_code == 401

    def test_revoke_all_client_keys(self, client, api_key):
        """La revocation par client desactive TOUTES ses cles."""
        resp = client.post("/admin/keys", json={
            "client_id": "test-company",
            "admin_token": settings.effective_admin_token,
        })
        second_key = resp.json()["api_key"]

        resp = _revoke(client, "test-company", settings.effective_admin_token)
        assert resp.json()["keys_revoked"] == 2

        for key in (api_key, second_key):
            assert client.post("/gateway/scan", json={"text": "test"},
                               headers={"X-SENTINEL-Key": key}).status_code == 401

    def test_revoke_bad_admin_token(self, client, api_key):
        assert _revoke(client, "test-company", "wrong-token").status_code == 403

    def test_revoke_unknown_client(self, client, api_key):
        resp = _revoke(client, "inconnu", settings.effective_admin_token)
        assert resp.status_code == 404


class TestRateLimit:
    def test_quota_exceeded_returns_429(self, client, api_key, monkeypatch):
        monkeypatch.setattr(settings, "rate_limit_per_minute", 3)
        headers = {"X-SENTINEL-Key": api_key}
        for _ in range(3):
            assert client.post("/gateway/scan", json={"text": "ok"},
                               headers=headers).status_code == 200
        resp = client.post("/gateway/scan", json={"text": "ok"}, headers=headers)
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers

    def test_quota_is_per_client(self, client, api_key, monkeypatch):
        """Le quota d'un client n'impacte pas les autres."""
        monkeypatch.setattr(settings, "rate_limit_per_minute", 3)
        resp = client.post("/admin/keys", json={
            "client_id": "autre-client",
            "admin_token": settings.effective_admin_token,
        })
        other_key = resp.json()["api_key"]

        headers = {"X-SENTINEL-Key": api_key}
        for _ in range(3):
            client.post("/gateway/scan", json={"text": "ok"}, headers=headers)
        assert client.post("/gateway/scan", json={"text": "ok"},
                           headers=headers).status_code == 429

        assert client.post("/gateway/scan", json={"text": "ok"},
                           headers={"X-SENTINEL-Key": other_key}).status_code == 200

    def test_zero_disables_limit(self, client, api_key, monkeypatch):
        monkeypatch.setattr(settings, "rate_limit_per_minute", 0)
        headers = {"X-SENTINEL-Key": api_key}
        for _ in range(10):
            assert client.post("/gateway/scan", json={"text": "ok"},
                               headers=headers).status_code == 200

    def test_bearer_endpoint_rate_limited(self, client, api_key, monkeypatch):
        """Le rate-limit s'applique aussi a l'endpoint OpenAI-compatible."""
        monkeypatch.setattr(settings, "rate_limit_per_minute", 1)
        body = {"model": "gpt-4o",
                "messages": [{"role": "user", "content": "bonjour"}]}
        headers = {"Authorization": f"Bearer {api_key}"}
        client.post("/v1/chat/completions", json=body, headers=headers)
        resp = client.post("/v1/chat/completions", json=body, headers=headers)
        assert resp.status_code == 429
