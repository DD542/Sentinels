"""
Tests du rapport de conformite (/compliance/report[.json]) : signature
HMAC re-verifiable, contenu, protection par token dashboard.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import pytest
from fastapi.testclient import TestClient

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


class TestComplianceReport:
    def test_signature_is_verifiable(self, client):
        """La signature HMAC du JSON canonique (sans le champ signature)
        se recalcule avec la cle d'audit."""
        report = client.get("/compliance/report.json").json()
        signature = report.pop("signature")
        canonical = json.dumps(report, sort_keys=True, ensure_ascii=False)
        expected = hmac.new(bytes.fromhex(settings.audit_hmac_key),
                            canonical.encode(), hashlib.sha256).hexdigest()
        assert signature == expected

    def test_report_reflects_activity(self, client, api_key):
        client.post("/gateway/scan",
                    json={"text": f"virement vers {IBAN}"},
                    headers={"X-SENTINEL-Key": api_key})
        report = client.get("/compliance/report.json").json()
        assert report["activity"]["prompts_scanned"] >= 1
        assert report["audit_chain"]["entries"] >= 1
        assert report["audit_chain"]["integrity_verified"] is True
        assert report["audit_chain"]["head_hash"]

    def test_html_report_renders(self, client):
        resp = client.get("/compliance/report")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/html")
        for section in ("Rapport de conformité", "Registre Shadow AI",
                        "Intégrité du journal", "Signature du rapport"):
            assert section in resp.text

    def test_protected_by_dashboard_token(self, client, monkeypatch):
        monkeypatch.setattr(settings, "dashboard_token", "dash-secret")
        assert client.get("/compliance/report.json").status_code == 401
        assert client.get("/compliance/report").status_code == 401
        assert client.get(
            "/compliance/report.json",
            headers={"X-Dashboard-Token": "dash-secret"}).status_code == 200
