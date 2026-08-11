"""
Tests de la revocation des sessions du dashboard.

Le scenario qui compte : un cookie VOLE. Il est cryptographiquement
valide et le restera jusqu'a son expiration — a moins d'un registre de
revocation. C'est ce que ces tests verifient, y compris le fait que se
deconnecter tue la session pour tout le monde, pas seulement pour le
navigateur qui efface son cookie.
"""
from __future__ import annotations
import time

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import get_settings
from app import revocation, sso

settings = get_settings()


@pytest.fixture
def client():
    return TestClient(app)


def _session(email="alice@monentreprise.fr", sub="user-123") -> str:
    return sso.issue_session({"sub": sub, "email": email, "name": "Alice"})


class TestPorteeSession:
    async def test_cookie_vole_devient_inutilisable(self):
        cookie = _session()
        vole = cookie                        # copie chez l'attaquant
        session = sso.read_session(cookie)
        assert session is not None

        await revocation.revoke_session(session["jti"])
        assert sso.read_session(vole) is None

    async def test_les_autres_sessions_survivent(self):
        c1, c2 = _session(), _session()
        await revocation.revoke_session(sso.read_session(c1)["jti"])
        assert sso.read_session(c1) is None
        assert sso.read_session(c2) is not None

    def test_chaque_session_a_un_identifiant_unique(self):
        jtis = {sso.read_session(_session())["jti"] for _ in range(5)}
        assert len(jtis) == 5


class TestPorteeCompte:
    async def test_revocation_par_adresse(self):
        """Depart d'un employe : toutes ses sessions tombent."""
        c1, c2 = _session(), _session()
        autre = _session(email="bob@monentreprise.fr", sub="user-999")

        await revocation.revoke_subject("alice@monentreprise.fr")
        assert sso.read_session(c1) is None
        assert sso.read_session(c2) is None
        assert sso.read_session(autre) is not None

    async def test_revocation_par_identifiant_technique(self):
        cookie = _session()
        await revocation.revoke_subject("user-123")
        assert sso.read_session(cookie) is None

    async def test_insensible_a_la_casse(self):
        cookie = _session(email="Alice@MonEntreprise.fr")
        await revocation.revoke_subject("alice@monentreprise.fr")
        assert sso.read_session(cookie) is None

    async def test_une_nouvelle_session_reste_valide(self):
        """Reactivation d'un compte : seules les sessions ANTERIEURES
        sont coupees, pas les futures."""
        await revocation.revoke_subject("alice@monentreprise.fr")
        time.sleep(1.1)                      # horodatage en secondes
        assert sso.read_session(_session()) is not None


class TestPorteeGlobale:
    async def test_tout_est_coupe(self):
        cookies = [_session(), _session(email="bob@x.fr", sub="u2")]
        await revocation.revoke_all()
        assert all(sso.read_session(c) is None for c in cookies)

    async def test_les_sessions_ulterieures_passent(self):
        await revocation.revoke_all()
        time.sleep(1.1)
        assert sso.read_session(_session()) is not None


class TestPurge:
    async def test_revocations_perimees_effacees(self):
        """Une revocation ne sert plus a rien quand la session visee
        aurait expire : le registre doit rester borne."""
        await revocation.revoke_session("session-ancienne")
        revocation._REVOKED_JTI["session-ancienne"] = time.time() - 86400
        await revocation.revoke_session("session-recente")

        assert await revocation.purge_expired(session_ttl_hours=8) == 1
        assert "session-ancienne" not in revocation._REVOKED_JTI
        assert "session-recente" in revocation._REVOKED_JTI

    async def test_purge_dans_la_maintenance(self):
        from app import maintenance
        resultat = await maintenance.run_once()
        assert "revocations_purged" in resultat


class TestEndpoints:
    def test_deconnexion_revoque_la_session(self, client):
        cookie = _session()
        client.cookies.set(sso.SESSION_COOKIE, cookie)
        assert client.post("/auth/logout").status_code == 200
        client.cookies.clear()
        # Le cookie est mort meme pour qui en avait garde une copie.
        assert sso.read_session(cookie) is None

    def test_revocation_compte_via_api(self, client, monkeypatch):
        monkeypatch.setattr(settings, "dashboard_token", "token-partage")
        cookie = _session()
        client.cookies.set(sso.SESSION_COOKIE, cookie)
        assert client.get("/dashboard/stats").status_code == 200

        resp = client.post("/auth/revoke", json={
            "admin_token": settings.effective_admin_token,
            "subject": "alice@monentreprise.fr"})
        assert resp.status_code == 200
        assert resp.json()["scope"] == "subject"
        assert resp.json()["audit_hash"]

        assert client.get("/dashboard/stats").status_code == 401
        client.cookies.clear()

    def test_revocation_globale_via_api(self, client):
        resp = client.post("/auth/revoke", json={
            "admin_token": settings.effective_admin_token,
            "all_sessions": True})
        assert resp.status_code == 200
        assert resp.json()["scope"] == "global"

    def test_token_admin_obligatoire(self, client):
        resp = client.post("/auth/revoke", json={
            "admin_token": "mauvais", "subject": "alice@x.fr"})
        assert resp.status_code == 403

    def test_cible_obligatoire(self, client):
        resp = client.post("/auth/revoke", json={
            "admin_token": settings.effective_admin_token})
        assert resp.status_code == 400
