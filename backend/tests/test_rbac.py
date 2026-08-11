"""
Tests des roles et permissions de la console.

Le point qui compte : un auditeur (DPO) doit pouvoir lire les rapports de
conformite et exercer les droits des personnes, mais **pas** creer de
cles ni consulter la facturation. Un observateur ne voit que le flux.

Un test verrouille aussi un piege rencontre pendant l'implementation :
le repli « installation de demonstration » ne doit JAMAIS accorder les
droits d'administration, sinon un mauvais jeton passerait.
"""
from __future__ import annotations
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import get_settings
from app import auth, policy, rbac, sso

settings = get_settings()


@pytest.fixture(autouse=True)
def etat_propre():
    auth._KEYS.clear()
    policy._reset()
    yield
    auth._KEYS.clear()
    policy._reset()


@pytest.fixture
def client():
    return TestClient(app)


def _session(role, email="alice@monentreprise.fr"):
    return sso.issue_session({"sub": "u1", "email": email, "role": role})


# ============================================================
# Matrice
# ============================================================

class TestMatrice:
    def test_administrateur_a_tout(self):
        perms = rbac.permissions(rbac.ADMIN)
        for p in (rbac.KEYS_MANAGE, rbac.USAGE_READ, rbac.GDPR_MANAGE,
                  rbac.COMPLIANCE_READ, rbac.AUDIT_VERIFY,
                  rbac.MAINTENANCE_RUN, rbac.DASHBOARD_READ):
            assert p in perms

    def test_auditeur_ni_cles_ni_facturation(self):
        """Un DPO n'a aucune raison de pouvoir creer un acces."""
        perms = rbac.permissions(rbac.AUDITOR)
        assert rbac.COMPLIANCE_READ in perms
        assert rbac.GDPR_MANAGE in perms
        assert rbac.AUDIT_VERIFY in perms
        assert rbac.KEYS_MANAGE not in perms
        assert rbac.USAGE_READ not in perms
        assert rbac.MAINTENANCE_RUN not in perms

    def test_observateur_lecture_seule(self):
        assert rbac.permissions(rbac.VIEWER) == {rbac.DASHBOARD_READ}

    def test_role_inconnu_sans_droit(self):
        assert rbac.permissions("directeur-general") == set()
        assert rbac.permissions(None) == set()


# ============================================================
# Attribution depuis le fournisseur d'identite
# ============================================================

class TestRolesDepuisGroupes:
    def test_correspondance(self, monkeypatch):
        monkeypatch.setattr(settings, "oidc_admin_groups", "rssi,it-admin")
        monkeypatch.setattr(settings, "oidc_auditor_groups", "dpo")
        monkeypatch.setattr(settings, "oidc_viewer_groups", "soc")
        assert rbac.role_from_groups(["rssi"]) == rbac.ADMIN
        assert rbac.role_from_groups(["dpo"]) == rbac.AUDITOR
        assert rbac.role_from_groups(["soc"]) == rbac.VIEWER

    def test_insensible_a_la_casse(self, monkeypatch):
        monkeypatch.setattr(settings, "oidc_admin_groups", "rssi")
        assert rbac.role_from_groups(["RSSI"]) == rbac.ADMIN

    def test_le_plus_fort_l_emporte(self, monkeypatch):
        monkeypatch.setattr(settings, "oidc_admin_groups", "rssi")
        monkeypatch.setattr(settings, "oidc_viewer_groups", "soc")
        assert rbac.role_from_groups(["soc", "rssi"]) == rbac.ADMIN

    def test_groupe_inconnu_sans_role(self, monkeypatch):
        monkeypatch.setattr(settings, "oidc_admin_groups", "rssi")
        assert rbac.role_from_groups(["stagiaires"]) is None

    def test_defaut_le_plus_faible(self):
        """Une configuration de groupes incomplete ne doit pas donner
        les droits d'administration."""
        assert rbac.default_sso_role() == rbac.VIEWER


# ============================================================
# Application aux endpoints
# ============================================================

class TestAcces:
    def test_auditeur_lit_la_conformite(self, client, monkeypatch):
        monkeypatch.setattr(settings, "dashboard_token", "tok-dash")
        client.cookies.set(sso.SESSION_COOKIE, _session(rbac.AUDITOR))
        assert client.get("/compliance/report.json").status_code == 200
        client.cookies.clear()

    def test_auditeur_ne_cree_pas_de_cle(self, client, monkeypatch):
        monkeypatch.setattr(settings, "dashboard_token", "tok-dash")
        client.cookies.set(sso.SESSION_COOKIE, _session(rbac.AUDITOR))
        resp = client.post("/admin/keys", json={"client_id": "x",
                                                "admin_token": ""})
        assert resp.status_code == 403
        assert "auditeur" in resp.json()["detail"]
        client.cookies.clear()

    def test_auditeur_ne_voit_pas_la_facturation(self, client, monkeypatch):
        monkeypatch.setattr(settings, "dashboard_token", "tok-dash")
        client.cookies.set(sso.SESSION_COOKIE, _session(rbac.AUDITOR))
        assert client.get("/admin/usage").status_code == 403
        client.cookies.clear()

    def test_auditeur_exerce_les_droits_rgpd(self, client, monkeypatch):
        monkeypatch.setattr(settings, "dashboard_token", "tok-dash")
        client.cookies.set(sso.SESSION_COOKIE, _session(rbac.AUDITOR))
        resp = client.post("/compliance/subject",
                           json={"value": "Jean Dupont", "admin_token": ""})
        assert resp.status_code == 200
        client.cookies.clear()

    def test_observateur_ne_lit_pas_la_conformite(self, client, monkeypatch):
        monkeypatch.setattr(settings, "dashboard_token", "tok-dash")
        client.cookies.set(sso.SESSION_COOKIE, _session(rbac.VIEWER))
        assert client.post("/compliance/subject",
                           json={"value": "x", "admin_token": ""}).status_code == 403
        client.cookies.clear()

    def test_administrateur_passe_partout(self, client, monkeypatch):
        monkeypatch.setattr(settings, "dashboard_token", "tok-dash")
        client.cookies.set(sso.SESSION_COOKIE, _session(rbac.ADMIN))
        assert client.get("/admin/usage").status_code == 200
        assert client.post("/admin/keys", json={"client_id": "x",
                                                "admin_token": ""}).status_code == 200
        client.cookies.clear()

    def test_jeton_admin_reste_accepte(self, client):
        """Compatibilite : l'automatisation continue d'utiliser le jeton."""
        resp = client.post("/admin/keys", json={
            "client_id": "auto", "admin_token": settings.effective_admin_token})
        assert resp.status_code == 200


class TestRepliDemonstration:
    def test_le_repli_n_accorde_jamais_l_administration(self, client):
        """Piege evite : sans jeton dashboard ni SSO, la console de
        LECTURE est ouverte — mais un mauvais jeton ne doit pas ouvrir
        les operations d'administration."""
        assert not settings.dashboard_token and not settings.sso_enabled
        assert rbac._role_depuis_les_jetons(None, None) == rbac.VIEWER

        resp = client.post("/admin/keys", json={"client_id": "x",
                                                "admin_token": "mauvais"})
        assert resp.status_code == 403

    def test_lecture_ouverte_en_demonstration(self, client):
        assert client.get("/dashboard/stats").status_code == 200


class TestIdentiteExposee:
    def test_me_sans_session(self, client):
        data = client.get("/auth/me").json()
        assert data["role"] == rbac.VIEWER      # mode demonstration
        assert data["permissions"] == ["dashboard:read"]

    def test_me_avec_session(self, client, monkeypatch):
        monkeypatch.setattr(settings, "dashboard_token", "tok-dash")
        client.cookies.set(sso.SESSION_COOKIE, _session(rbac.AUDITOR))
        data = client.get("/auth/me").json()
        assert data["authenticated"] is True
        assert data["role"] == rbac.AUDITOR
        assert "compliance:read" in data["permissions"]
        assert "keys:manage" not in data["permissions"]
        assert data["email"] == "alice@monentreprise.fr"
        client.cookies.clear()
