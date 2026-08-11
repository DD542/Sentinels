"""
Tests du streaming natif : desanonymisation incrementale et endpoint SSE.

Le cas critique : un jeton FPE peut etre COUPE entre deux fragments du
fournisseur. Une substitution fragment par fragment le manquerait, et
l'employe recevrait la valeur factice au lieu de la sienne.
"""
from __future__ import annotations
import json
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import get_settings
from app.detection.types import EntityType
from app.vault import fpe
from app import auth
from app.gateway import openai_compat

settings = get_settings()
IBAN = "FR7610107001011234567890129"


def _detok(*pairs) -> fpe.IncrementalDetokenizer:
    return fpe.IncrementalDetokenizer(
        {token: (real, etype) for token, real, etype in pairs})


class TestIncrementalDetokenizer:
    def test_jeton_coupe_entre_deux_fragments(self):
        """Le cas qui casse une substitution naive."""
        d = _detok(("FR2473620249543191490730570", IBAN, EntityType.IBAN))
        sortie = "".join([
            d.feed("Le virement vers FR247362"),
            d.feed("0249543191490730570 est programme."),
            d.flush(),
        ])
        assert IBAN in sortie
        assert "FR2473620249543191490730570" not in sortie

    def test_jeton_coupe_caractere_par_caractere(self):
        """Cas extreme : le fournisseur emet lettre par lettre."""
        token = "FR2473620249543191490730570"
        d = _detok((token, IBAN, EntityType.IBAN))
        texte = f"vers {token} merci"
        sortie = "".join(d.feed(c) for c in texte) + d.flush()
        assert sortie == f"vers {IBAN} merci"

    def test_nom_restaure(self):
        d = _detok(("Hugo Blanc", "Jean Dupont", EntityType.PERSON))
        sortie = "".join([d.feed("Bonjour Hugo "), d.feed("Blanc, "),
                          d.feed("voici."), d.flush()])
        assert sortie == "Bonjour Jean Dupont, voici."

    def test_plusieurs_jetons(self):
        d = _detok(("Hugo Blanc", "Jean Dupont", EntityType.PERSON),
                   ("FR2473620249543191490730570", IBAN, EntityType.IBAN))
        fragments = ["Hugo Bl", "anc doit virer sur FR24736202",
                     "49543191490730570 avant lundi."]
        sortie = "".join(d.feed(f) for f in fragments) + d.flush()
        assert "Jean Dupont" in sortie
        assert IBAN in sortie

    def test_texte_sans_jeton_traverse_intact(self):
        d = _detok(("Hugo Blanc", "Jean Dupont", EntityType.PERSON))
        fragments = ["Bonjour, ", "comment ", "allez-vous ?"]
        sortie = "".join(d.feed(f) for f in fragments) + d.flush()
        assert sortie == "Bonjour, comment allez-vous ?"

    def test_sans_candidat_passe_plat_immediat(self):
        """Aucun jeton connu : rien a retenir, latence nulle."""
        d = _detok()
        assert d.feed("bonjour") == "bonjour"
        assert d.flush() == ""

    def test_rien_ne_reste_apres_flush(self):
        d = _detok(("Hugo Blanc", "Jean Dupont", EntityType.PERSON))
        d.feed("un texte avec Hugo Blanc dedans")
        d.flush()
        assert d.flush() == ""

    def test_tolerance_aux_separateurs(self):
        """Le modele reformate le jeton en ajoutant des espaces."""
        d = _detok(("FR2473620249543191490730570", IBAN, EntityType.IBAN))
        sortie = d.feed("vers FR24 7362 0249 5431 9149 0730 570 ok") + d.flush()
        assert IBAN in sortie

    def test_valeur_restauree_non_retraitee(self):
        """La vraie valeur traverse les passes suivantes sans etre alteree."""
        d = _detok(("FR2473620249543191490730570", IBAN, EntityType.IBAN))
        sortie = "".join([d.feed(f"vers FR2473620249543191490730570 "),
                          d.feed("puis rien."), d.flush()])
        assert sortie.count(IBAN) == 1


# ============================================================
# Endpoint /v1/chat/completions en streaming natif
# ============================================================

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
def flux_fournisseur(monkeypatch):
    """Simule un fournisseur qui emet le jeton FPE en deux morceaux."""
    async def _fake(provider, model, messages, max_tokens, temperature=None):
        recu = messages[-1]["content"]
        token = next((mot for mot in recu.split() if mot.startswith("FR")), "")
        yield "Le virement vers ", None, None
        yield token[:8], None, None            # jeton coupe en plein milieu
        yield token[8:], None, None
        yield " est programme.", "stop", None
        yield "", None, {"prompt_tokens": 10, "completion_tokens": 5,
                         "total_tokens": 15}

    monkeypatch.setattr(openai_compat, "_stream_v1", _fake)


def _contenu_sse(texte: str) -> tuple[str, str | None, dict | None]:
    contenu, finish, usage = "", None, None
    for ligne in texte.split("\n"):
        if not ligne.startswith("data: ") or ligne == "data: [DONE]":
            continue
        data = json.loads(ligne[6:])
        if data.get("usage"):
            usage = data["usage"]
        for choix in data.get("choices", []):
            contenu += choix.get("delta", {}).get("content", "")
            finish = choix.get("finish_reason") or finish
    return contenu, finish, usage


class TestNativeStreamEndpoint:
    def test_vraie_valeur_restauree_dans_le_flux(self, client, api_key,
                                                 flux_fournisseur):
        resp = client.post("/v1/chat/completions", json={
            "model": "gpt-4o", "stream": True,
            "messages": [{"role": "user", "content": f"vire sur {IBAN}"}],
        }, headers={"Authorization": f"Bearer {api_key}"})

        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")
        contenu, finish, usage = _contenu_sse(resp.text)
        assert IBAN in contenu                    # jeton recolle et restaure
        assert finish == "stop"
        assert usage["total_tokens"] == 15
        assert resp.text.rstrip().endswith("data: [DONE]")

    def test_erreur_fournisseur_en_cours_de_flux(self, client, api_key,
                                                 monkeypatch):
        """Le flux a deja commence : on ne peut plus renvoyer un code HTTP,
        l'erreur doit etre signalee dans le flux."""
        async def _casse(provider, model, messages, max_tokens,
                         temperature=None):
            yield "debut de reponse", None, None
            raise RuntimeError("connexion perdue")

        monkeypatch.setattr(openai_compat, "_stream_v1", _casse)
        resp = client.post("/v1/chat/completions", json={
            "model": "gpt-4o", "stream": True,
            "messages": [{"role": "user", "content": "bonjour"}],
        }, headers={"Authorization": f"Bearer {api_key}"})

        contenu, finish, _ = _contenu_sse(resp.text)
        assert "debut de reponse" in contenu
        assert finish == "error"
        assert resp.text.rstrip().endswith("data: [DONE]")

    def test_mode_simule_conserve(self, client, api_key, monkeypatch):
        """STREAM_NATIVE=false : on revient au decoupage apres coup."""
        monkeypatch.setattr(settings, "stream_native", False)

        async def _fake(provider, model, messages, max_tokens,
                        temperature=None):
            return f"Reponse : {messages[-1]['content']}", dict(
                prompt_tokens=1, completion_tokens=1, total_tokens=2)

        monkeypatch.setattr(openai_compat, "_forward_v1", _fake)
        resp = client.post("/v1/chat/completions", json={
            "model": "gpt-4o", "stream": True,
            "messages": [{"role": "user", "content": f"vire sur {IBAN}"}],
        }, headers={"Authorization": f"Bearer {api_key}"})

        contenu, _, _ = _contenu_sse(resp.text)
        assert IBAN in contenu


class TestSsePayloadParsing:
    def test_lignes_ignorees(self):
        for ligne in ("", ": commentaire", "event: ping", "data: [DONE]",
                      "data: pas du json"):
            assert openai_compat._sse_payloads(ligne) is None

    def test_ligne_valide(self):
        assert openai_compat._sse_payloads('data: {"a": 1}') == {"a": 1}
