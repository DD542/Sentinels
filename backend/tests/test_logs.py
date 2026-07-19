"""
Tests des logs structures JSON : formatter, evenements metier emis aux
points de passage, absence de donnees sensibles dans les logs.
"""
from __future__ import annotations
import json
import logging
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import get_settings
from app import auth
from app import logs

settings = get_settings()
IBAN = "FR7610107001011234567890129"


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record):
        self.records.append(record)


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


@pytest.fixture
def capture():
    handler = _Capture()
    root = logging.getLogger("sentinel")
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    yield handler
    root.removeHandler(handler)


class TestJsonFormatter:
    def test_valid_json_with_extras(self):
        record = logging.LogRecord(
            name="sentinel.test", level=logging.INFO, pathname=__file__,
            lineno=1, msg="decision", args=(), exc_info=None)
        record.event = "decision"
        record.entity_type = "IBAN"
        out = json.loads(logs.JsonFormatter().format(record))
        assert out["message"] == "decision"
        assert out["level"] == "INFO"
        assert out["logger"] == "sentinel.test"
        assert out["event"] == "decision"
        assert out["entity_type"] == "IBAN"
        assert "ts" in out

    def test_configure_is_idempotent(self):
        logs.configure()
        logs.configure()
        assert len(logging.getLogger("sentinel").handlers) == 1


class TestBusinessEvents:
    def test_decision_logged_on_scan(self, client, api_key, capture):
        client.post("/gateway/scan",
                    json={"text": f"virement vers {IBAN}"},
                    headers={"X-SENTINEL-Key": api_key})
        decisions = [r for r in capture.records
                     if getattr(r, "event", None) == "decision"]
        assert any(getattr(r, "entity_type", None) == "IBAN"
                   and getattr(r, "action", None) == "TOKENIZE"
                   for r in decisions)

    def test_sensitive_value_never_logged(self, client, api_key, capture):
        """La valeur detectee ne doit JAMAIS apparaitre dans les logs."""
        client.post("/gateway/scan",
                    json={"text": f"virement vers {IBAN}"},
                    headers={"X-SENTINEL-Key": api_key})
        fmt = logs.JsonFormatter()
        for r in capture.records:
            assert IBAN not in fmt.format(r)

    def test_rate_limited_logged(self, client, api_key, capture, monkeypatch):
        monkeypatch.setattr(settings, "rate_limit_per_minute", 1)
        headers = {"X-SENTINEL-Key": api_key}
        client.post("/gateway/scan", json={"text": "ok"}, headers=headers)
        client.post("/gateway/scan", json={"text": "ok"}, headers=headers)
        limited = [r for r in capture.records
                   if getattr(r, "event", None) == "rate_limited"]
        assert limited and limited[0].client_id == "test-company"
        assert limited[0].levelname == "WARNING"
