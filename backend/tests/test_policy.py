"""
Tests du reglage de detection par client.

Le faux positif est le vrai risque d'adoption : si SENTINEL tokenise la
raison sociale du client a chaque prompt, l'employe contourne l'outil.
Ces tests verifient que le reglage fonctionne, qu'il reste cloisonne
entre clients, et surtout qu'il ne peut pas affaiblir la protection en
silence.
"""
from __future__ import annotations
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import get_settings
from app.detection.types import Action, EntityType, Finding
from app import auth, policy
from app.audit import chain

settings = get_settings()
IBAN = "FR7610107001011234567890129"


@pytest.fixture(autouse=True)
def reset_policies():
    auth._KEYS.clear()
    policy._reset()
    yield
    auth._KEYS.clear()
    policy._reset()


@pytest.fixture
def client():
    return TestClient(app)


def _cle(client, client_id="acme"):
    resp = client.post("/admin/keys", json={
        "client_id": client_id,
        "admin_token": settings.effective_admin_token})
    return resp.json()["api_key"]


def _finding(valeur, etype=EntityType.PERSON, confiance=0.85):
    return Finding(entity_type=etype, start=0, end=len(valeur), value=valeur,
                   confidence=confiance, layer="L2")


# ============================================================
# Validation
# ============================================================

class TestValidation:
    def test_politique_vide_acceptee(self):
        assert policy.validate({}) == policy.empty_policy()

    def test_type_inconnu_refuse(self):
        with pytest.raises(ValueError, match="Type inconnu"):
            policy.validate({"actions": {"CHAT_GPT": "ALLOW"}})

    def test_action_inconnue_refusee(self):
        with pytest.raises(ValueError, match="Action inconnue"):
            policy.validate({"actions": {"PERSON": "IGNORER"}})

    def test_seuil_hors_bornes_refuse(self):
        with pytest.raises(ValueError, match="hors de"):
            policy.validate({"min_confidence": {"PERSON": 1.5}})

    def test_allowlist_bornee(self):
        with pytest.raises(ValueError, match="1000"):
            policy.validate({"allowlist": [f"v{i}" for i in range(1001)]})

    def test_valeurs_vides_nettoyees(self):
        v = policy.validate({"allowlist": ["  Acme  ", "", "   "]})
        assert v["allowlist"] == ["Acme"]


# ============================================================
# Application
# ============================================================

class TestExceptions:
    async def test_exception_ecarte_la_detection(self):
        await policy.set_policy("acme", {"allowlist": ["Martin"]})
        retenus, ecartes = policy.filter_findings(
            [_finding("Martin"), _finding("Jean Dupont")], "acme")
        assert [f.value for f in retenus] == ["Jean Dupont"]
        assert ecartes[0][1] == "exception"

    async def test_insensible_casse_accents_separateurs(self):
        await policy.set_policy("acme", {"allowlist": ["Martin & Associés"]})
        for variante in ("martin associes", "MARTIN & ASSOCIES",
                         "Martin  &  Associés"):
            retenus, _ = policy.filter_findings([_finding(variante)], "acme")
            assert retenus == [], variante

    async def test_correspondance_exacte_seulement(self):
        """Une correspondance partielle supprimerait silencieusement des
        detections voisines : inacceptable pour un controle de securite."""
        await policy.set_policy("acme", {"allowlist": ["Martin"]})
        retenus, _ = policy.filter_findings([_finding("Martin Dupont")], "acme")
        assert len(retenus) == 1        # PAS ecarte

    async def test_cloisonnement_entre_clients(self):
        await policy.set_policy("acme", {"allowlist": ["Martin"]})
        retenus, _ = policy.filter_findings([_finding("Martin")], "autre")
        assert len(retenus) == 1        # la politique d'acme ne s'applique pas


class TestSeuils:
    async def test_seuil_par_type(self):
        await policy.set_policy("acme", {"min_confidence": {"PERSON": 0.9}})
        retenus, ecartes = policy.filter_findings([
            _finding("Jean", EntityType.PERSON, 0.85),      # ecarte
            _finding("Marie", EntityType.PERSON, 0.95),     # garde
            _finding(IBAN, EntityType.IBAN, 0.5),           # autre type : garde
        ], "acme")
        assert {f.value for f in retenus} == {"Marie", IBAN}
        assert ecartes[0][1] == "sous le seuil"

    async def test_sans_politique_rien_n_est_ecarte(self):
        findings = [_finding("Jean", confiance=0.1)]
        retenus, ecartes = policy.filter_findings(findings, "vierge")
        assert retenus == findings and ecartes == []


class TestActions:
    async def test_surcharge_d_action(self):
        from app.detection.engine import DetectionEngine
        moteur = DetectionEngine()
        secret = _finding("sk-xxx", EntityType.SECRET, 0.99)

        assert moteur.decide(secret, "acme") == Action.BLOCK    # defaut
        await policy.set_policy("acme", {"actions": {"SECRET": "ALLOW"}})
        assert moteur.decide(secret, "acme") == Action.ALLOW    # surcharge
        assert moteur.decide(secret, "autre") == Action.BLOCK   # cloisonne


# ============================================================
# Garde-fous : un reglage ne doit pas affaiblir en silence
# ============================================================

class TestGardeFous:
    async def test_degradation_signalee(self):
        applique = await policy.set_policy("acme", {
            "actions": {"SECRET": "ALLOW"}})
        alertes = policy.degradations(applique)
        assert any("SECRET" in a for a in alertes)

    async def test_seuil_extreme_signale(self):
        applique = await policy.set_policy("acme", {
            "min_confidence": {"PERSON": 0.99}})
        assert policy.degradations(applique)

    async def test_politique_saine_sans_alerte(self):
        applique = await policy.set_policy("acme", {
            "allowlist": ["Acme"], "min_confidence": {"PERSON": 0.7}})
        assert policy.degradations(applique) == []

    async def test_agregat_pour_le_rapport(self):
        await policy.set_policy("acme", {"actions": {"IP_LEAK": "ALLOW"}})
        await policy.set_policy("sain", {"allowlist": ["X"]})
        agrege = policy.all_degradations()
        assert [d["client_id"] for d in agrege] == ["acme"]
        # Le rapport ne divulgue aucune valeur d'exception.
        assert "X" not in repr(agrege)


# ============================================================
# API
# ============================================================

class TestEndpoints:
    def test_lecture_politique_vide(self, client):
        cle = _cle(client)
        data = client.get("/policy", headers={"X-SENTINEL-Key": cle}).json()
        assert data["client_id"] == "acme"
        assert data["allowlist"] == []

    def test_ecriture_et_relecture(self, client):
        cle = _cle(client)
        resp = client.put("/policy", headers={"X-SENTINEL-Key": cle}, json={
            "allowlist": ["Acme Corp"], "min_confidence": {"PERSON": 0.8}})
        assert resp.status_code == 200
        assert resp.json()["audit_hash"]

        relu = client.get("/policy", headers={"X-SENTINEL-Key": cle}).json()
        assert relu["allowlist"] == ["Acme Corp"]
        assert relu["min_confidence"] == {"PERSON": 0.8}

    def test_politique_invalide_refusee(self, client):
        cle = _cle(client)
        resp = client.put("/policy", headers={"X-SENTINEL-Key": cle},
                          json={"actions": {"PERSON": "N_IMPORTE_QUOI"}})
        assert resp.status_code == 400

    def test_modification_scellee_dans_l_audit(self, client):
        cle = _cle(client)
        avant = chain.count()
        client.put("/policy", headers={"X-SENTINEL-Key": cle},
                   json={"actions": {"SECRET": "ALLOW"}})
        assert chain.count() > avant
        derniere = chain._CHAIN[-1]
        assert derniere["action"] == "POLICY_UPDATE"
        # Le detail scelle contient la degradation.
        detail = chain.read_detail(derniere)
        assert detail and detail["degradations"]

    def test_authentification_requise(self, client):
        _cle(client)                       # des qu'une cle existe, auth stricte
        assert client.get("/policy").status_code == 401
        assert client.put("/policy", json={}).status_code == 401

    def test_effet_reel_sur_un_scan(self, client):
        """Bout en bout : une exception fait disparaitre la detection."""
        cle = _cle(client)
        entetes = {"X-SENTINEL-Key": cle}

        avant = client.post("/gateway/scan", headers=entetes,
                            json={"text": f"virement vers {IBAN}"}).json()
        assert any(d["type"] == "IBAN" for d in avant["decisions"])

        client.put("/policy", headers=entetes, json={"allowlist": [IBAN]})
        apres = client.post("/gateway/scan", headers=entetes,
                            json={"text": f"virement vers {IBAN}"}).json()
        assert not any(d["type"] == "IBAN" for d in apres["decisions"])
        assert IBAN in apres["sanitized"]   # laisse tel quel
