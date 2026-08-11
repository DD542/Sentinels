"""
Tests du SSO d'entreprise (OpenID Connect).

Un faux fournisseur d'identite complet est monte ici : paire RSA, JWKS,
jetons signes. La verification de signature est donc reellement
exercee — un test qui se contenterait de jetons factices ne prouverait
rien sur la partie qui compte.
"""
from __future__ import annotations
import base64
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.main import app
from app.config import get_settings
from app import sso
from app.audit import chain

settings = get_settings()

ISSUER = "https://idp.test"
CLIENT_ID = "sentinel-test"

_cle = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwks_key():
    """Clé publique au format JWKS."""
    nombres = _cle.public_key().public_numbers()

    def b64(entier: int) -> str:
        octets = entier.to_bytes((entier.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(octets).decode().rstrip("=")

    return {"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256",
            "n": b64(nombres.n), "e": b64(nombres.e)}


def _id_token(**surcharges) -> str:
    claims = {
        "iss": ISSUER, "aud": CLIENT_ID, "sub": "user-123",
        "email": "alice@monentreprise.fr", "email_verified": True,
        "name": "Alice Martin", "groups": ["rssi"],
        "iat": int(time.time()), "exp": int(time.time()) + 600,
    }
    claims.update(surcharges)
    return jwt.encode(claims, _cle, algorithm="RS256",
                      headers={"kid": "test-key"})


@pytest.fixture
def idp(monkeypatch):
    """Active le SSO et court-circuite la decouverte reseau."""
    monkeypatch.setattr(settings, "oidc_issuer", ISSUER)
    monkeypatch.setattr(settings, "oidc_client_id", CLIENT_ID)
    monkeypatch.setattr(settings, "oidc_client_secret", "secret")
    monkeypatch.setattr(settings, "oidc_allowed_domains", "monentreprise.fr")
    monkeypatch.setattr(settings, "oidc_allowed_groups", "")
    monkeypatch.setattr(settings, "session_cookie_secure", False)

    decouverte = {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "jwks_uri": f"{ISSUER}/jwks",
    }

    class _FauxJWKClient:
        def __init__(self, uri): pass

        def get_signing_key_from_jwt(self, token):
            return jwt.PyJWK(_jwks_key())

    sso._discovery = decouverte
    sso._jwks_client = _FauxJWKClient(decouverte["jwks_uri"])
    yield decouverte
    sso._reset_discovery_cache()


@pytest.fixture
def client():
    return TestClient(app)


# ============================================================
# Session
# ============================================================

class TestSession:
    def test_aller_retour(self):
        identite = {"sub": "u1", "email": "a@b.fr", "name": "A"}
        lu = sso.read_session(sso.issue_session(identite))
        assert lu["email"] == "a@b.fr"

    def test_cookie_altere_rejete(self):
        jeton = sso.issue_session({"sub": "u1", "email": "a@b.fr"})
        assert sso.read_session(jeton[:-4] + "AAAA") is None

    def test_cookie_absent(self):
        assert sso.read_session(None) is None
        assert sso.read_session("") is None

    def test_identite_non_lisible_en_clair(self):
        """Le cookie est chiffre, pas seulement signe."""
        jeton = sso.issue_session({"sub": "u1", "email": "alice@exemple.fr"})
        assert "alice" not in jeton

    def test_session_expiree(self, monkeypatch):
        monkeypatch.setattr(settings, "session_ttl_hours", 0)
        jeton = sso.issue_session({"sub": "u1", "email": "a@b.fr"})
        time.sleep(1.1)
        assert sso.read_session(jeton) is None


# ============================================================
# Controle d'acces
# ============================================================

class TestAuthorize:
    def test_refus_sans_restriction(self, monkeypatch):
        """Le defaut doit etre fermé : sinon n'importe quel compte du
        fournisseur (Google, Entra multi-tenant) entrerait."""
        monkeypatch.setattr(settings, "oidc_allowed_domains", "")
        monkeypatch.setattr(settings, "oidc_allowed_groups", "")
        assert sso.authorize({"email": "alice@monentreprise.fr"}) is not None

    def test_domaine_autorise(self, monkeypatch):
        monkeypatch.setattr(settings, "oidc_allowed_domains", "monentreprise.fr")
        monkeypatch.setattr(settings, "oidc_allowed_groups", "")
        assert sso.authorize({"email": "alice@monentreprise.fr",
                              "email_verified": True}) is None

    def test_domaine_etranger_refuse(self, monkeypatch):
        monkeypatch.setattr(settings, "oidc_allowed_domains", "monentreprise.fr")
        monkeypatch.setattr(settings, "oidc_allowed_groups", "")
        assert sso.authorize({"email": "pirate@gmail.com",
                              "email_verified": True}) is not None

    def test_adresse_non_verifiee_refusee(self, monkeypatch):
        monkeypatch.setattr(settings, "oidc_allowed_domains", "monentreprise.fr")
        monkeypatch.setattr(settings, "oidc_allowed_groups", "")
        assert sso.authorize({"email": "alice@monentreprise.fr",
                              "email_verified": False}) is not None

    def test_groupe_autorise(self, monkeypatch):
        monkeypatch.setattr(settings, "oidc_allowed_domains", "")
        monkeypatch.setattr(settings, "oidc_allowed_groups", "rssi,dpo")
        assert sso.authorize({"email": "x@ailleurs.fr",
                              "groups": ["RSSI"]}) is None
        assert sso.authorize({"email": "x@ailleurs.fr",
                              "groups": ["stagiaires"]}) is not None


# ============================================================
# Verification du jeton d'identite
# ============================================================

class TestIdToken:
    def test_jeton_valide(self, idp):
        claims = sso.verify_id_token(_id_token(nonce="n1"), nonce="n1")
        assert claims["email"] == "alice@monentreprise.fr"

    def test_signature_etrangere_rejetee(self, idp):
        autre = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        faux = jwt.encode({"iss": ISSUER, "aud": CLIENT_ID, "sub": "x",
                           "iat": int(time.time()),
                           "exp": int(time.time()) + 600},
                          autre, algorithm="RS256",
                          headers={"kid": "test-key"})
        with pytest.raises(Exception) as exc:
            sso.verify_id_token(faux)
        assert "401" in str(exc.value) or "invalide" in str(exc.value)

    def test_jeton_expire_rejete(self, idp):
        with pytest.raises(Exception):
            sso.verify_id_token(_id_token(exp=int(time.time()) - 10))

    def test_mauvaise_audience_rejetee(self, idp):
        with pytest.raises(Exception):
            sso.verify_id_token(_id_token(aud="une-autre-application"))

    def test_mauvais_emetteur_rejete(self, idp):
        with pytest.raises(Exception):
            sso.verify_id_token(_id_token(iss="https://idp-pirate.test"))

    def test_nonce_invalide_rejete(self, idp):
        with pytest.raises(Exception):
            sso.verify_id_token(_id_token(nonce="attendu"), nonce="different")

    def test_algorithme_none_rejete(self, idp):
        """Attaque classique : jeton non signe declare alg=none."""
        entete = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "kid": "test-key"}).encode()).decode().rstrip("=")
        corps = base64.urlsafe_b64encode(json.dumps(
            {"iss": ISSUER, "aud": CLIENT_ID, "sub": "pirate",
             "iat": int(time.time()), "exp": int(time.time()) + 600}
        ).encode()).decode().rstrip("=")
        with pytest.raises(Exception):
            sso.verify_id_token(f"{entete}.{corps}.")


# ============================================================
# Flux et acces au dashboard
# ============================================================

class TestFlux:
    def test_config_publique(self, client, idp):
        data = client.get("/auth/config").json()
        assert data["sso_enabled"] is True
        assert data["login_url"] == "/auth/login"

    def test_config_sans_sso(self, client):
        assert client.get("/auth/config").json()["sso_enabled"] is False

    def test_login_redirige_vers_le_fournisseur(self, client, idp):
        resp = client.get("/auth/login", follow_redirects=False)
        assert resp.status_code == 302
        cible = resp.headers["location"]
        assert cible.startswith(f"{ISSUER}/authorize")
        for param in ("code_challenge=", "code_challenge_method=S256",
                      "state=", "nonce=", "client_id=" + CLIENT_ID):
            assert param in cible
        assert sso._STATE_COOKIE in resp.cookies

    def test_login_absent_sans_sso(self, client):
        assert client.get("/auth/login").status_code == 404

    def test_callback_sans_contexte_refuse(self, client, idp):
        """Sans le cookie d'état, la requête ne vient pas de nous (CSRF)."""
        resp = client.get("/auth/callback?code=abc&state=xyz",
                          follow_redirects=False)
        assert resp.status_code == 400

    def test_redirection_ouverte_bloquee(self):
        assert sso._safe_next("//evil.com") == "/"
        assert sso._safe_next("https://evil.com") == "/"
        assert sso._safe_next("/dashboard") == "/dashboard"
        assert sso._safe_next(None) == "/"


class TestAccesDashboard:
    def test_session_ouvre_le_dashboard(self, client, monkeypatch):
        """Une session SSO remplace le token partagé."""
        monkeypatch.setattr(settings, "dashboard_token", "token-partage")
        assert client.get("/dashboard/stats").status_code == 401

        client.cookies.set(sso.SESSION_COOKIE,
                           sso.issue_session({"sub": "u1",
                                              "email": "alice@monentreprise.fr"}))
        assert client.get("/dashboard/stats").status_code == 200
        client.cookies.clear()

    def test_token_reste_un_acces_de_secours(self, client, monkeypatch):
        monkeypatch.setattr(settings, "dashboard_token", "token-partage")
        resp = client.get("/dashboard/stats",
                          headers={"X-Dashboard-Token": "token-partage"})
        assert resp.status_code == 200

    def test_websocket_accepte_la_session(self, client, monkeypatch):
        monkeypatch.setattr(settings, "dashboard_token", "token-partage")
        client.cookies.set(sso.SESSION_COOKIE,
                           sso.issue_session({"sub": "u1", "email": "a@b.fr"}))
        with client.websocket_connect("/dashboard/ws") as ws:
            assert ws.receive_json()["kind"] == "snapshot"
        client.cookies.clear()

    def test_logout_efface_la_session(self, client):
        resp = client.post("/auth/logout")
        assert resp.status_code == 200
        assert "sentinel_session=" in resp.headers.get("set-cookie", "")
