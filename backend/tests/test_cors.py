"""
Origines autorisees : configurables, jamais permissives.

Le defaut corrige : la liste etait codee en dur sur `localhost:5173`.
Deployer la console sur un vrai domaine imposait d'editer le code source
et de reconstruire l'image — c'est-a-dire de forker le produit pour
l'installer.

L'autre moitie du probleme est l'inverse : le reflexe, face a un CORS qui
bloque, est de mettre `*`. Avec un cookie de session, ca laisserait
n'importe quel site visite par un administrateur piloter la console a son
insu. La configuration doit donc etre possible ET bornee.
"""
from __future__ import annotations
import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import app

settings = get_settings()


@pytest.fixture
def client():
    return TestClient(app)


class TestListeEffective:
    def test_vide_donne_les_origines_de_developpement(self, monkeypatch):
        monkeypatch.setattr(settings, "cors_origins", "")
        assert "http://127.0.0.1:5173" in settings.effective_cors_origins

    def test_liste_configuree(self, monkeypatch):
        monkeypatch.setattr(settings, "cors_origins",
                            "https://a.exemple.fr, https://b.exemple.fr")
        assert settings.effective_cors_origins == [
            "https://a.exemple.fr", "https://b.exemple.fr"]

    def test_barre_finale_normalisee(self, monkeypatch):
        """Le navigateur envoie une origine SANS barre finale : la
        laisser ferait echouer la comparaison sans aucun message utile."""
        monkeypatch.setattr(settings, "cors_origins",
                            "https://console.exemple.fr/")
        assert settings.effective_cors_origins == ["https://console.exemple.fr"]

    def test_joker_refuse(self, monkeypatch):
        monkeypatch.setattr(settings, "cors_origins", "*")
        with pytest.raises(ValueError, match="cookie|joker|'\\*'"):
            settings.effective_cors_origins

    def test_joker_refuse_meme_melange(self, monkeypatch):
        monkeypatch.setattr(settings, "cors_origins",
                            "https://a.exemple.fr,*")
        with pytest.raises(ValueError):
            settings.effective_cors_origins


class TestReponseHttp:
    def test_origine_de_developpement_autorisee(self, client):
        r = client.get("/health", headers={"Origin": "http://127.0.0.1:5173"})
        assert r.headers.get("access-control-allow-origin") == \
            "http://127.0.0.1:5173"

    def test_origine_inconnue_non_autorisee(self, client):
        """Le middleware repond 200 mais SANS l'en-tete : c'est le
        navigateur qui bloque. L'absence d'en-tete est le controle."""
        r = client.get("/health", headers={"Origin": "https://evil.example"})
        assert "access-control-allow-origin" not in r.headers

    def test_preflight_de_l_origine_autorisee(self, client):
        r = client.options("/gateway/scan", headers={
            "Origin": "http://127.0.0.1:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type"})
        assert r.status_code == 200
        assert r.headers.get("access-control-allow-credentials") == "true"
