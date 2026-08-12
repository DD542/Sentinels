"""
`/v1/models` et `/v1/embeddings` : les deux endpoints dont l'absence
faisait contourner la passerelle.

  * **`/v1/models` en 404** — Open WebUI, LibreChat et Cursor l'appellent
    au premier contact pour peupler leur selecteur. Un 404 leur fait
    conclure « base_url invalide » : l'integrateur repointe l'outil
    directement sur OpenAI. Le controle n'est pas contourne par
    malveillance, mais parce qu'il avait l'air casse.

  * **`/v1/embeddings` en 404** — une chaine RAG vectorise TOUS les
    documents de l'entreprise. Cette seule etape etait pointee
    directement sur le fournisseur : contrats, dossiers RH et fichiers
    clients partaient en entier, hors de toute inspection, alors que le
    chat, lui, etait protege.
"""
from __future__ import annotations
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import get_settings
from app.gateway import openai_compat
from app import auth

settings = get_settings()
IBAN = "FR7610107001011234567890129"


@pytest.fixture(autouse=True)
def reset():
    auth._KEYS.clear()
    openai_compat._reset_catalogue_cache()
    yield
    auth._KEYS.clear()
    openai_compat._reset_catalogue_cache()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def cle(client):
    return client.post("/admin/keys", json={
        "client_id": "catalogue",
        "admin_token": settings.effective_admin_token}).json()["api_key"]


def _h(cle):
    return {"Authorization": f"Bearer {cle}"}


@pytest.fixture
def openai_configure(monkeypatch):
    monkeypatch.setattr(settings, "openai_api_key", "sk-test")
    monkeypatch.setattr(settings, "anthropic_api_key", "")
    monkeypatch.setattr(settings, "mistral_api_key", "")
    monkeypatch.setattr(settings, "groq_api_key", "")


# ============================================================
# /v1/models
# ============================================================

class TestCatalogue:
    def test_authentification_exigee(self, client, cle, openai_configure):
        # `cle` est demandee pour sortir du mode bootstrap (aucune cle
        # enregistree = deploiement neuf, ouvert le temps de la config).
        assert client.get("/v1/models").status_code == 401

    def test_format_openai(self, client, cle, openai_configure, monkeypatch):
        async def _faux(provider):
            return ["gpt-4o", "gpt-4o-mini"]
        monkeypatch.setattr(openai_compat, "_catalogue_fournisseur", _faux)

        corps = client.get("/v1/models", headers=_h(cle)).json()
        assert corps["object"] == "list"
        ids = [m["id"] for m in corps["data"]]
        assert ids == ["gpt-4o", "gpt-4o-mini"]
        assert all(m["object"] == "model" and m["owned_by"] == "openai"
                   for m in corps["data"])

    def test_fournisseur_sans_cle_absent(self, client, cle, openai_configure,
                                         monkeypatch):
        """Annoncer un modele non servable produirait un 503 au premier
        message : l'utilisateur croirait la passerelle en panne."""
        async def _faux(provider):
            return [f"modele-{provider}"]
        monkeypatch.setattr(openai_compat, "_catalogue_fournisseur", _faux)

        ids = [m["id"] for m in client.get("/v1/models", headers=_h(cle)).json()["data"]]
        assert ids == ["modele-openai"]

    def test_repli_si_fournisseur_injoignable(self, client, cle,
                                              openai_configure, monkeypatch):
        """Une panne amont ne doit pas vider le selecteur du client."""
        class _Casse:
            def __init__(self, *a, **k): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            async def get(self, *a, **k): raise RuntimeError("reseau")

        monkeypatch.setattr(openai_compat.httpx, "AsyncClient", _Casse)
        ids = [m["id"] for m in client.get("/v1/models", headers=_h(cle)).json()["data"]]
        assert "gpt-4o" in ids

    def test_seuls_les_modeles_routables_annonces(self):
        """`dall-e-3` finirait chez Groq : l'annoncer garantirait une
        erreur amont incomprehensible."""
        assert openai_compat._routable("openai", "gpt-4o")
        assert openai_compat._routable("openai", "text-embedding-3-small")
        assert not openai_compat._routable("openai", "dall-e-3")
        assert not openai_compat._routable("openai", "whisper-1")
        assert not openai_compat._routable("groq", "whisper-large-v3")

    def test_modele_unitaire(self, client, cle, openai_configure):
        corps = client.get("/v1/models/gpt-4o", headers=_h(cle)).json()
        assert corps["id"] == "gpt-4o"
        assert corps["owned_by"] == "openai"

    def test_modele_unitaire_sans_cle(self, client, cle, openai_configure):
        assert client.get("/v1/models/claude-sonnet-4-5",
                          headers=_h(cle)).status_code == 404


# ============================================================
# /v1/embeddings
# ============================================================

@pytest.fixture
def fournisseur_embeddings(monkeypatch, openai_configure):
    """Capture ce qui part reellement chez le fournisseur."""
    capture = {}

    class _Reponse:
        status_code = 200
        def raise_for_status(self): pass
        def json(self):
            return {"object": "list", "model": "text-embedding-3-small",
                    "data": [{"object": "embedding", "index": i,
                              "embedding": [0.1, 0.2]}
                             for i in range(len(capture["json"]["input"]))],
                    "usage": {"prompt_tokens": 5, "total_tokens": 5}}

    class _Client:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, headers=None, json=None):
            capture["url"] = url
            capture["json"] = json
            return _Reponse()

    monkeypatch.setattr(openai_compat.httpx, "AsyncClient", _Client)
    return capture


class TestEmbeddings:
    def test_texte_sensible_jamais_transmis(self, client, cle,
                                            fournisseur_embeddings):
        """LE test : c'est exactement ce qui partait en clair avant."""
        r = client.post("/v1/embeddings", headers=_h(cle), json={
            "model": "text-embedding-3-small",
            "input": f"Contrat de Jean Dupont, IBAN {IBAN}"})
        assert r.status_code == 200
        assert IBAN not in str(fournisseur_embeddings["json"])

    def test_lot_de_documents_assaini_entierement(self, client, cle,
                                                  fournisseur_embeddings):
        """Une indexation RAG envoie des centaines de fragments d'un coup :
        en assainir un sur deux ne servirait a rien."""
        r = client.post("/v1/embeddings", headers=_h(cle), json={
            "model": "text-embedding-3-small",
            "input": ["chapitre neutre", f"annexe : {IBAN}",
                      "conclusion neutre"]})
        assert r.status_code == 200
        envoye = fournisseur_embeddings["json"]["input"]
        assert len(envoye) == 3
        assert IBAN not in str(envoye)

    def test_reponse_du_fournisseur_relayee(self, client, cle,
                                            fournisseur_embeddings):
        """Les vecteurs ne portent pas de texte : rien a restaurer, mais
        la forme doit rester celle d'OpenAI."""
        corps = client.post("/v1/embeddings", headers=_h(cle), json={
            "model": "text-embedding-3-small", "input": ["a", "b"]}).json()
        assert corps["object"] == "list"
        assert len(corps["data"]) == 2
        assert corps["data"][0]["embedding"] == [0.1, 0.2]
        assert corps["usage"]["total_tokens"] == 5

    def test_substitution_stable_donc_recherche_utilisable(
            self, client, cle, fournisseur_embeddings):
        """La valeur pseudonymisee doit etre IDENTIQUE d'un appel a
        l'autre, sinon deux occurrences du meme nom donneraient deux
        vecteurs eloignes et la recherche semantique s'ecroulerait."""
        envois = []
        for _ in range(2):
            client.post("/v1/embeddings", headers=_h(cle), json={
                "model": "text-embedding-3-small",
                "input": f"dossier de Jean Dupont, {IBAN}"})
            envois.append(fournisseur_embeddings["json"]["input"][0])
        assert envois[0] == envois[1]

    def test_parametres_relayes(self, client, cle, fournisseur_embeddings):
        client.post("/v1/embeddings", headers=_h(cle), json={
            "model": "text-embedding-3-small", "input": "x",
            "dimensions": 256, "encoding_format": "float", "user": "u-1"})
        envoye = fournisseur_embeddings["json"]
        assert envoye["dimensions"] == 256
        assert envoye["encoding_format"] == "float"
        assert envoye["user"] == "u-1"

    def test_entree_deja_tokenisee_refusee(self, client, cle,
                                           fournisseur_embeddings):
        """Des identifiants BPE ne sont pas inspectables. Les relayer
        donnerait l'illusion d'un controle qui n'a pas lieu."""
        r = client.post("/v1/embeddings", headers=_h(cle), json={
            "model": "text-embedding-3-small", "input": [[1234, 5678]]})
        assert r.status_code == 400
        assert "url" not in fournisseur_embeddings   # rien n'est parti

    def test_entree_vide_refusee(self, client, cle, fournisseur_embeddings):
        assert client.post("/v1/embeddings", headers=_h(cle), json={
            "model": "text-embedding-3-small", "input": []}).status_code == 400

    def test_modele_inconnu_message_explicite(self, client, cle,
                                              fournisseur_embeddings):
        r = client.post("/v1/embeddings", headers=_h(cle), json={
            "model": "gpt-4o", "input": "x"})
        assert r.status_code == 400
        assert "text-embedding-3-small" in str(r.json())

    def test_mistral_route_vers_mistral(self, client, cle, monkeypatch,
                                        fournisseur_embeddings):
        monkeypatch.setattr(settings, "mistral_api_key", "sk-mistral")
        client.post("/v1/embeddings", headers=_h(cle), json={
            "model": "mistral-embed", "input": "x"})
        assert fournisseur_embeddings["url"].startswith(settings.mistral_base)

    def test_authentification_exigee(self, client, cle, fournisseur_embeddings):
        assert client.post("/v1/embeddings", json={
            "model": "text-embedding-3-small", "input": "x"}).status_code == 401
