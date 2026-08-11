"""
Fidelite de la passerelle compatible OpenAI.

Defaut corrige : le modele de requete n'acceptait que `role` et
`content: str`. Consequence mesuree — `tools` et `tool_choice`
silencieusement abandonnes avec un HTTP 200, contenu multimodal refuse
en 422, `top_p` / `seed` / `response_format` ignores. L'integration du
client cassait SANS ERREUR, et la faute semblait venir de chez lui.

Deux regles verrouillees ici :
  1. rien n'est perdu en silence — tout champ inconnu est relaye ;
  2. rien n'est relaye sans etre assaini — y compris les arguments
     d'appel d'outil, ou un agent place typiquement l'IBAN.
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
def reset_keys():
    auth._KEYS.clear()
    yield
    auth._KEYS.clear()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def cle(client):
    return client.post("/admin/keys", json={
        "client_id": "fidelite",
        "admin_token": settings.effective_admin_token}).json()["api_key"]


@pytest.fixture
def fournisseur(monkeypatch):
    """Capture ce qui part, et repond par un appel d'outil dont les
    arguments contiennent le JETON — comme le ferait un vrai modele."""
    capture = {}

    async def _faux(provider, model, messages, max_tokens, temperature=None,
                    extras=None):
        capture["messages"] = messages
        capture["extras"] = extras or {}
        jeton = ""
        for m in messages:
            contenu = m.get("content")
            if isinstance(contenu, str):
                jeton = next((w.strip(".,") for w in contenu.split()
                              if w.startswith("FR")), jeton)
        return ({"role": "assistant", "content": None,
                 "tool_calls": [{"id": "c1", "type": "function", "function": {
                     "name": "virer",
                     "arguments": '{"iban":"%s"}' % jeton}}],
                 "_finish_reason": "tool_calls"},
                {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})

    monkeypatch.setattr(openai_compat, "_forward_v1", _faux)
    monkeypatch.setattr(settings, "stream_native", False)
    return capture


def _h(cle):
    return {"Authorization": f"Bearer {cle}"}


class TestAppelsOutil:
    def test_outils_relayes(self, client, cle, fournisseur):
        r = client.post("/v1/chat/completions", headers=_h(cle), json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "quel temps a Paris"}],
            "tools": [{"type": "function", "function": {
                "name": "meteo", "description": "Temps qu'il fait",
                "parameters": {"type": "object", "properties": {}}}}],
            "tool_choice": "auto"})
        assert r.status_code == 200
        assert "tools" in fournisseur["extras"]
        assert fournisseur["extras"]["tool_choice"] == "auto"

    def test_schema_des_outils_intact(self, client, cle, fournisseur):
        """Seule la description est assainie : toucher au schema JSON
        rendrait l'outil inutilisable."""
        client.post("/v1/chat/completions", headers=_h(cle), json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "bonjour"}],
            "tools": [{"type": "function", "function": {
                "name": "virer", "description": "Vire vers un compte",
                "parameters": {"type": "object",
                               "properties": {"iban": {"type": "string"}},
                               "required": ["iban"]}}}]})
        schema = fournisseur["extras"]["tools"][0]["function"]["parameters"]
        assert schema["required"] == ["iban"]
        assert schema["properties"]["iban"]["type"] == "string"

    def test_reponse_avec_tool_calls_relayee(self, client, cle, fournisseur):
        """Auparavant la reponse etait reconstruite a partir du seul
        texte : un appel d'outil disparaissait entierement."""
        r = client.post("/v1/chat/completions", headers=_h(cle), json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": f"vire sur {IBAN}"}]})
        choix = r.json()["choices"][0]
        assert choix["finish_reason"] == "tool_calls"
        assert choix["message"]["tool_calls"][0]["function"]["name"] == "virer"

    def test_arguments_restaures_pour_l_outil(self, client, cle, fournisseur):
        """LE test : l'outil du client doit recevoir le VRAI IBAN, sinon
        il virerait de l'argent vers un compte factice."""
        r = client.post("/v1/chat/completions", headers=_h(cle), json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": f"vire sur {IBAN}"}]})
        args = r.json()["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
        assert IBAN in args

    def test_fournisseur_ne_voit_pas_la_vraie_valeur(self, client, cle, fournisseur):
        client.post("/v1/chat/completions", headers=_h(cle), json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": f"vire sur {IBAN}"}]})
        assert IBAN not in str(fournisseur["messages"])

    def test_arguments_de_l_historique_assainis(self, client, cle, fournisseur):
        """Un agent place la donnee sensible dans les arguments : les
        laisser passer viderait la passerelle de son sens."""
        client.post("/v1/chat/completions", headers=_h(cle), json={
            "model": "gpt-4o", "messages": [
                {"role": "assistant", "content": None, "tool_calls": [
                    {"id": "c1", "type": "function", "function": {
                        "name": "solde", "arguments": '{"iban":"%s"}' % IBAN}}]},
                {"role": "tool", "tool_call_id": "c1",
                 "content": f"Solde de {IBAN}"}]})
        envoye = str(fournisseur["messages"])
        assert IBAN not in envoye
        assert "tool_calls" in envoye        # structure conservee
        assert "tool_call_id" in envoye


class TestMultimodal:
    def test_contenu_en_liste_accepte(self, client, cle, fournisseur):
        """Auparavant : HTTP 422, requete refusee."""
        r = client.post("/v1/chat/completions", headers=_h(cle), json={
            "model": "gpt-4o", "messages": [{"role": "user", "content": [
                {"type": "text", "text": "bonjour"}]}]})
        assert r.status_code == 200

    def test_partie_texte_assainie(self, client, cle, fournisseur):
        client.post("/v1/chat/completions", headers=_h(cle), json={
            "model": "gpt-4o", "messages": [{"role": "user", "content": [
                {"type": "text", "text": f"analyse {IBAN}"}]}]})
        assert IBAN not in str(fournisseur["messages"])

    def test_partie_image_intacte(self, client, cle, fournisseur):
        """Inspecter une image n'aurait aucun sens ; l'alterer casserait
        la requete."""
        client.post("/v1/chat/completions", headers=_h(cle), json={
            "model": "gpt-4o", "messages": [{"role": "user", "content": [
                {"type": "text", "text": "decris"},
                {"type": "image_url",
                 "image_url": {"url": "data:image/png;base64,iVBOR"}}]}]})
        parties = fournisseur["messages"][0]["content"]
        assert parties[1]["image_url"]["url"] == "data:image/png;base64,iVBOR"


class TestParametres:
    def test_parametres_de_generation_relayes(self, client, cle, fournisseur):
        client.post("/v1/chat/completions", headers=_h(cle), json={
            "model": "gpt-4o", "messages": [{"role": "user", "content": "x"}],
            "top_p": 0.5, "seed": 42, "frequency_penalty": 0.3,
            "presence_penalty": 0.1, "stop": ["FIN"], "user": "u-42"})
        ex = fournisseur["extras"]
        for champ in ("top_p", "seed", "frequency_penalty",
                      "presence_penalty", "stop", "user"):
            assert champ in ex, f"{champ} abandonne"

    def test_response_format_relaye(self, client, cle, fournisseur):
        """Une application qui attend du JSON recevrait de la prose."""
        client.post("/v1/chat/completions", headers=_h(cle), json={
            "model": "gpt-4o", "messages": [{"role": "user", "content": "x"}],
            "response_format": {"type": "json_object"}})
        assert fournisseur["extras"]["response_format"] == {"type": "json_object"}

    def test_champs_internes_non_dupliques(self, client, cle, fournisseur):
        """`model`, `messages`, `stream`… sont interpretes par SENTINEL :
        ils ne doivent pas etre relayes une seconde fois."""
        client.post("/v1/chat/completions", headers=_h(cle), json={
            "model": "gpt-4o", "messages": [{"role": "user", "content": "x"}],
            "temperature": 0.2, "stream": False})
        for interne in ("model", "messages", "stream", "temperature"):
            assert interne not in fournisseur["extras"]


class TestStreamingOutils:
    def test_arguments_restaures_en_flux(self, client, cle, monkeypatch):
        """Les arguments d'outil arrivent en fragments : un jeton coupe
        entre deux fragments doit quand meme etre restaure."""
        monkeypatch.setattr(settings, "stream_native", True)

        async def _flux(provider, model, messages, max_tokens,
                        temperature=None, extras=None):
            contenu = messages[-1]["content"]
            jeton = next((w for w in contenu.split() if w.startswith("FR")), "")
            yield {"tool_calls": [{"index": 0, "id": "c1", "function": {
                "name": "virer", "arguments": '{"iban":"'}}]}, None, None
            yield {"tool_calls": [{"index": 0, "function": {
                "arguments": jeton[:10]}}]}, None, None      # coupe
            yield {"tool_calls": [{"index": 0, "function": {
                "arguments": jeton[10:]}}]}, None, None
            yield {"tool_calls": [{"index": 0, "function": {
                "arguments": '"}'}}]}, "tool_calls", None
            yield {}, None, {"prompt_tokens": 1, "completion_tokens": 1,
                             "total_tokens": 2}

        monkeypatch.setattr(openai_compat, "_stream_v1", _flux)
        r = client.post("/v1/chat/completions", headers=_h(cle), json={
            "model": "gpt-4o", "stream": True,
            "messages": [{"role": "user", "content": f"vire sur {IBAN}"}]})

        import json as _j
        arguments = ""
        for ligne in r.text.split("\n"):
            if not ligne.startswith("data: ") or ligne == "data: [DONE]":
                continue
            for choix in _j.loads(ligne[6:]).get("choices", []):
                for appel in (choix.get("delta", {}).get("tool_calls") or []):
                    arguments += appel.get("function", {}).get("arguments", "")
        assert IBAN in arguments
