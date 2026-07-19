"""
Tests d'authentification du dashboard : API stats/reset (header
X-Dashboard-Token) et WebSocket temps reel (sous-protocole sentinel.v1).
Sans DASHBOARD_TOKEN configure, l'acces reste libre (mode dev/demo).
"""
from __future__ import annotations
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.main import app
from app.config import get_settings

settings = get_settings()
TOKEN = "dash-secret-token-123"


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def protected(monkeypatch):
    monkeypatch.setattr(settings, "dashboard_token", TOKEN)


class TestOpenMode:
    def test_stats_open_without_token(self, client):
        assert client.get("/dashboard/stats").status_code == 200

    def test_ws_open_without_token(self, client):
        with client.websocket_connect("/dashboard/ws") as ws:
            snap = ws.receive_json()
            assert snap["kind"] == "snapshot"


class TestProtectedMode:
    def test_stats_requires_token(self, client, protected):
        assert client.get("/dashboard/stats").status_code == 401

    def test_stats_wrong_token(self, client, protected):
        resp = client.get("/dashboard/stats",
                          headers={"X-Dashboard-Token": "mauvais-token"})
        assert resp.status_code == 401

    def test_stats_valid_token(self, client, protected):
        resp = client.get("/dashboard/stats",
                          headers={"X-Dashboard-Token": TOKEN})
        assert resp.status_code == 200
        assert "audit_integrity" in resp.json()

    def test_reset_requires_token(self, client, protected):
        assert client.post("/dashboard/reset").status_code == 401

    def test_ws_rejected_without_token(self, client, protected):
        """Sans sous-protocole token, la connexion est fermee en 1008
        avant tout envoi de donnees."""
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect("/dashboard/ws") as ws:
                ws.receive_json()
        assert exc.value.code == 1008

    def test_ws_rejected_wrong_token(self, client, protected):
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect(
                    "/dashboard/ws",
                    subprotocols=["sentinel.v1", "mauvais-token"]) as ws:
                ws.receive_json()
        assert exc.value.code == 1008

    def test_ws_accepted_with_token(self, client, protected):
        with client.websocket_connect(
                "/dashboard/ws",
                subprotocols=["sentinel.v1", TOKEN]) as ws:
            snap = ws.receive_json()
            assert snap["kind"] == "snapshot"
