"""
Tests d'isolation multi-tenant de la couche L3 : le corpus confidentiel
du client A ne doit jamais influencer les scans du client B — ni bloquer
ses requetes, ni reveler l'existence de ses documents.
"""
from __future__ import annotations
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import get_settings
from app.detection import l3_semantic
from app import auth

settings = get_settings()

DOC_TEXT = ("Le montant total de la prestation s eleve a quatre cent "
            "cinquante mille euros hors taxes payable en douze echeances "
            "trimestrielles selon les conditions generales de vente "
            "applicables au territoire metropolitain.")
EXCERPT = ("Le montant total de la prestation s eleve a quatre cent "
           "cinquante mille euros hors taxes payable en douze echeances "
           "trimestrielles")


@pytest.fixture(autouse=True)
def reset_keys():
    auth._KEYS.clear()
    yield
    auth._KEYS.clear()


@pytest.fixture
def client():
    return TestClient(app)


def _make_key(client, client_id):
    resp = client.post("/admin/keys", json={
        "client_id": client_id,
        "admin_token": settings.effective_admin_token,
    })
    assert resp.status_code == 200
    return resp.json()["api_key"]


class TestCorpusIsolation:
    def test_leak_blocked_for_owner_only(self, client):
        """Le document du client A bloque A, mais pas B."""
        key_a = _make_key(client, "client-a")
        key_b = _make_key(client, "client-b")

        client.post("/corpus/ingest",
                    json={"doc_id": "contrat-a", "text": DOC_TEXT},
                    headers={"X-SENTINEL-Key": key_a})

        resp_a = client.post("/gateway/scan", json={"text": EXCERPT},
                             headers={"X-SENTINEL-Key": key_a})
        assert resp_a.json()["blocked"] is True

        resp_b = client.post("/gateway/scan", json={"text": EXCERPT},
                             headers={"X-SENTINEL-Key": key_b})
        assert resp_b.json()["blocked"] is False

    def test_stats_are_per_client(self, client):
        """Les stats corpus ne revelent que le corpus du client authentifie."""
        key_a = _make_key(client, "client-a")
        key_b = _make_key(client, "client-b")

        client.post("/corpus/ingest",
                    json={"doc_id": "contrat-a", "text": DOC_TEXT},
                    headers={"X-SENTINEL-Key": key_a})

        stats_a = client.get("/corpus/stats",
                             headers={"X-SENTINEL-Key": key_a}).json()
        stats_b = client.get("/corpus/stats",
                             headers={"X-SENTINEL-Key": key_b}).json()
        assert stats_a["shingles_indexed"] > 0
        assert stats_b["shingles_indexed"] == 0

    def test_stats_require_key_once_created(self, client):
        """Des qu'une cle existe, /corpus/stats sans cle est rejete."""
        _make_key(client, "client-a")
        assert client.get("/corpus/stats").status_code == 401

    def test_scan_sync_isolated_by_client(self):
        """Isolation au niveau module, sans passer par l'API."""
        l3_semantic.ingest_document("doc-x", DOC_TEXT, client_id="tenant-1")
        assert l3_semantic.scan_sync(EXCERPT, client_id="tenant-1")
        assert l3_semantic.scan_sync(EXCERPT, client_id="tenant-2") == []
        assert l3_semantic.scan_sync(EXCERPT) == []  # client "default"
