"""
Tests du cloisonnement de la chaine d'audit par tenant.

Avant : une seule chaine globale ou les entrees de tous les clients
s'entrelacaient. Exporter le journal d'un client aurait revele
l'existence des entrees des autres, et aucun client ne pouvait obtenir
une chaine verifiable qui lui soit propre.

Apres : une chaine par client, verifiable independamment.
"""
from __future__ import annotations
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import get_settings
from app import auth
from app.audit import chain

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


def _cle(client, client_id):
    return client.post("/admin/keys", json={
        "client_id": client_id,
        "admin_token": settings.effective_admin_token}).json()["api_key"]


class TestChainesSeparees:
    def test_chaque_client_a_sa_chaine(self):
        a = chain.append("TOKENIZE", "IBAN", "IBAN:0", {"v": 1}, tenant="acme")
        b = chain.append("TOKENIZE", "IBAN", "IBAN:0", {"v": 2}, tenant="globex")

        # Chacune part de la genese : aucune n'est chainee sur l'autre.
        assert a["prev_hash"] == chain._GENESIS
        assert b["prev_hash"] == chain._GENESIS
        assert chain.head("acme") == a["hash"]
        assert chain.head("globex") == b["hash"]

    def test_chainage_interne_a_chaque_client(self):
        a1 = chain.append("TOKENIZE", "IBAN", "IBAN:0", {"v": 1}, tenant="acme")
        chain.append("TOKENIZE", "IBAN", "IBAN:1", {"v": 2}, tenant="globex")
        a2 = chain.append("TOKENIZE", "IBAN", "IBAN:2", {"v": 3}, tenant="acme")
        # a2 suit a1 malgre l'entree de globex intercalee.
        assert a2["prev_hash"] == a1["hash"]

    def test_comptes_separes(self):
        for _ in range(3):
            chain.append("TOKENIZE", "IBAN", "IBAN:0", {"v": 1}, tenant="acme")
        chain.append("TOKENIZE", "IBAN", "IBAN:0", {"v": 1}, tenant="globex")
        assert chain.count("acme") == 3
        assert chain.count("globex") == 1
        assert chain.count() == 4              # total

    def test_le_tenant_est_scelle(self):
        """Sans ca, on pourrait deplacer une entree d'une chaine a
        l'autre sans casser le hachage."""
        e = chain.append("TOKENIZE", "IBAN", "IBAN:0", {"v": 1}, tenant="acme")
        e["tenant"] = "globex"
        assert chain.verify_integrity() is False

    def test_chaine_exploitant_sans_champ_tenant(self):
        """Les entrees d'administration (et l'historique anterieur au
        cloisonnement) restent scellees sans le champ : leur hash doit
        rester verifiable a l'identique."""
        e = chain.append("KEY_REVOKED", "ADMIN", "client-a", {"n": 1})
        assert "tenant" not in e
        assert chain.verify_integrity() is True


class TestVerificationIndependante:
    def test_chaque_chaine_se_verifie_seule(self):
        chain.append("TOKENIZE", "IBAN", "IBAN:0", {"v": 1}, tenant="acme")
        chain.append("TOKENIZE", "IBAN", "IBAN:0", {"v": 2}, tenant="globex")
        assert chain.verify_integrity("acme") is True
        assert chain.verify_integrity("globex") is True
        assert chain.verify_integrity() is True

    def test_alteration_isolee_a_sa_chaine(self):
        """Le point qui compte : une falsification chez un client ne doit
        pas invalider la preuve d'un autre."""
        chain.append("TOKENIZE", "IBAN", "IBAN:0", {"v": 1}, tenant="acme")
        chain.append("TOKENIZE", "IBAN", "IBAN:0", {"v": 2}, tenant="globex")
        chain._CHAIN[0]["action"] = "ALLOW"          # falsifie acme

        assert chain.verify_integrity("acme") is False
        assert chain.verify_integrity("globex") is True   # intacte
        assert chain.verify_integrity() is False          # globalement KO

    async def test_incrementale_couvre_toutes_les_chaines(self):
        chain.append("TOKENIZE", "IBAN", "IBAN:0", {"v": 1}, tenant="acme")
        chain.append("TOKENIZE", "IBAN", "IBAN:0", {"v": 2}, tenant="globex")
        premier = await chain.verify_incremental()
        assert premier["verified"] is True and premier["checked"] == 2

        chain.append("TOKENIZE", "IBAN", "IBAN:1", {"v": 3}, tenant="acme")
        second = await chain.verify_incremental()
        assert second["checked"] == 1            # seulement la nouvelle


class TestExport:
    async def test_export_ne_contient_que_le_client(self):
        chain.append("TOKENIZE", "IBAN", "IBAN:0", {"v": 1}, tenant="acme")
        chain.append("TOKENIZE", "IBAN", "IBAN:1", {"v": 2}, tenant="acme")
        chain.append("TOKENIZE", "IBAN", "IBAN:0", {"v": 3}, tenant="globex")

        export = await chain.export_tenant("acme")
        assert export["count"] == 2
        assert all(e.get("tenant") == "acme" for e in export["entries"])
        assert export["chain_linkage_valid"] is True
        # Aucune trace de l'autre client.
        assert "globex" not in repr(export)

    async def test_detail_reste_chiffre(self):
        chain.append("TOKENIZE", "PERSON", "PERSON:0",
                     {"value": "Jean Dupont"}, subject="Jean Dupont",
                     tenant="acme")
        export = await chain.export_tenant("acme")
        assert "Jean Dupont" not in repr(export)

    async def test_export_vide_pour_client_inconnu(self):
        export = await chain.export_tenant("jamais-vu")
        assert export["count"] == 0
        assert export["chain_linkage_valid"] is True   # vide = trivialement OK


class TestEndpoint:
    def test_export_du_client_authentifie(self, client):
        cle_a = _cle(client, "acme")
        cle_b = _cle(client, "globex")
        client.post("/gateway/scan", headers={"X-SENTINEL-Key": cle_a},
                    json={"text": f"virement vers {IBAN}"})
        client.post("/gateway/scan", headers={"X-SENTINEL-Key": cle_b},
                    json={"text": "bonjour Marie Curie"})

        export = client.get("/audit/export",
                            headers={"X-SENTINEL-Key": cle_a}).json()
        assert export["tenant"] == "acme"
        assert export["count"] >= 1
        assert export["chain_linkage_valid"] is True
        assert all(e.get("tenant") == "acme" for e in export["entries"])

    def test_un_client_ne_voit_pas_l_autre(self, client):
        cle_a = _cle(client, "acme")
        cle_b = _cle(client, "globex")
        client.post("/gateway/scan", headers={"X-SENTINEL-Key": cle_a},
                    json={"text": f"virement vers {IBAN}"})

        export_b = client.get("/audit/export",
                              headers={"X-SENTINEL-Key": cle_b}).json()
        assert export_b["count"] == 0        # rien de acme ne transparait

    def test_authentification_requise(self, client):
        _cle(client, "acme")
        assert client.get("/audit/export").status_code == 401
