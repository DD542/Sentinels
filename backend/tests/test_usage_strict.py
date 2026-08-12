"""
Tests du metering par client (/admin/usage — base de facturation) et du
mode strict fail-closed (refus de demarrer avec une posture incomplete).
"""
from __future__ import annotations
import pytest
from fastapi.testclient import TestClient

from app.main import app, enforce_strict_mode
from app.config import get_settings
from app import auth
from app import events

settings = get_settings()
IBAN = "FR7610107001011234567890129"


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


def _make_key(client, client_id):
    resp = client.post("/admin/keys", json={
        "client_id": client_id,
        "admin_token": settings.effective_admin_token,
    })
    return resp.json()["api_key"]


class TestUsageMetering:
    def test_usage_per_client(self, client):
        """Chaque client a ses compteurs : la base d'une facturation."""
        key_a = _make_key(client, "client-a")
        key_b = _make_key(client, "client-b")

        client.post("/gateway/scan", json={"text": f"virement {IBAN}"},
                    headers={"X-SENTINEL-Key": key_a})
        client.post("/gateway/scan", json={"text": "bonjour"},
                    headers={"X-SENTINEL-Key": key_a})
        client.post("/gateway/scan", json={"text": "bonjour"},
                    headers={"X-SENTINEL-Key": key_b})

        resp = client.get("/admin/usage", headers={
            "X-Admin-Token": settings.effective_admin_token})
        assert resp.status_code == 200
        usage = resp.json()
        assert usage["clients"]["client-a"]["prompts"] == 2
        assert usage["clients"]["client-a"]["tokenized"] >= 1
        assert usage["clients"]["client-b"]["prompts"] == 1
        assert usage["clients"]["client-b"]["tokenized"] == 0
        assert usage["total_prompts"] == 3

    def test_usage_requires_admin_token(self, client):
        assert client.get("/admin/usage").status_code == 403
        assert client.get("/admin/usage", headers={
            "X-Admin-Token": "mauvais"}).status_code == 403


class TestStrictMode:
    def test_incomplete_posture_refused(self, monkeypatch):
        """Sans persistance ni tokens, le mode strict refuse de demarrer
        et nomme chaque probleme."""
        monkeypatch.setattr(settings, "database_url", "")
        monkeypatch.setattr(settings, "admin_token", "")
        monkeypatch.setattr(settings, "dashboard_token", "")
        with pytest.raises(RuntimeError) as exc:
            enforce_strict_mode()
        msg = str(exc.value)
        assert "database_url" in msg
        assert "admin_token" in msg
        assert "dashboard_token" in msg

    def _posture_complete(self, monkeypatch):
        monkeypatch.setattr(settings, "database_url", "postgresql://x")
        monkeypatch.setattr(settings, "vault_master_key", "a" * 64)
        monkeypatch.setattr(settings, "audit_hmac_key", "b" * 64)
        monkeypatch.setattr(settings, "admin_token", "tok-admin")
        monkeypatch.setattr(settings, "dashboard_token", "tok-dash")
        monkeypatch.setattr(settings, "cors_origins",
                            "https://sentinel.exemple.fr")

    def test_complete_posture_accepted(self, monkeypatch):
        self._posture_complete(monkeypatch)
        enforce_strict_mode()  # ne doit pas lever

    def test_cors_par_defaut_refuse(self, monkeypatch):
        """Le defaut n'autorise que localhost : demarrer en production
        avec, c'est livrer une console injoignable depuis son domaine."""
        self._posture_complete(monkeypatch)
        monkeypatch.setattr(settings, "cors_origins", "")
        with pytest.raises(RuntimeError, match="cors_origins"):
            enforce_strict_mode()

    def test_cors_joker_refuse(self, monkeypatch):
        """`*` est doublement mauvais : les navigateurs le rejettent avec
        des requetes authentifiees, et le silence de ce rejet ferait
        chercher la panne pendant des heures."""
        self._posture_complete(monkeypatch)
        monkeypatch.setattr(settings, "cors_origins", "*")
        with pytest.raises(RuntimeError, match="joker|'\\*'"):
            enforce_strict_mode()
