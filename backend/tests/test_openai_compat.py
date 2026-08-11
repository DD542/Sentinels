"""
Tests d'integration de l'endpoint compatible OpenAI (/v1/chat/completions)
et du durcissement admin. Le fournisseur amont est simule (monkeypatch) :
aucun appel reseau.
"""
from __future__ import annotations
import json
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import get_settings
from app.gateway import openai_compat
from app.gateway import proxy
from app import auth

IBAN = "FR7610107001011234567890129"
settings = get_settings()


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
    assert resp.status_code == 200
    return resp.json()["api_key"]


@pytest.fixture
def fake_provider(monkeypatch):
    """Remplace l'appel fournisseur : renvoie en echo le dernier message
    recu (donc le contenu deja assaini) et capture ce qui a ete transmis."""
    captured = {}

    async def _fake(provider, model, messages, max_tokens, temperature=None):
        captured["provider"] = provider
        captured["messages"] = messages
        captured["temperature"] = temperature
        echo = messages[-1]["content"]
        return f"Reponse concernant : {echo}", {
            "prompt_tokens": 12, "completion_tokens": 7, "total_tokens": 19}

    monkeypatch.setattr(openai_compat, "_forward_v1", _fake)
    return captured


def _bearer(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


class TestOpenAICompat:
    def test_provider_never_sees_real_data(self, client, api_key, fake_provider):
        resp = client.post("/v1/chat/completions", json={
            "model": "gpt-4o",
            "messages": [{"role": "user",
                          "content": f"vire sur {IBAN} merci"}],
        }, headers=_bearer(api_key))
        assert resp.status_code == 200
        forwarded = fake_provider["messages"][-1]["content"]
        assert IBAN not in forwarded

    def test_answer_is_detokenized(self, client, api_key, fake_provider):
        """Le fournisseur repond avec le token FPE : le client final doit
        recevoir la vraie valeur restauree."""
        resp = client.post("/v1/chat/completions", json={
            "model": "gpt-4o",
            "messages": [{"role": "user",
                          "content": f"vire sur {IBAN} merci"}],
        }, headers=_bearer(api_key))
        content = resp.json()["choices"][0]["message"]["content"]
        assert IBAN in content

    def test_system_role_sanitized(self, client, api_key, fake_provider):
        """Un IBAN dans le prompt system doit aussi etre tokenise."""
        client.post("/v1/chat/completions", json={
            "model": "gpt-4o",
            "messages": [
                {"role": "system",
                 "content": f"Le compte de reference est {IBAN}."},
                {"role": "user", "content": "bonjour"},
            ],
        }, headers=_bearer(api_key))
        system_forwarded = fake_provider["messages"][0]["content"]
        assert IBAN not in system_forwarded

    def test_usage_and_temperature_passthrough(self, client, api_key, fake_provider):
        resp = client.post("/v1/chat/completions", json={
            "model": "gpt-4o",
            "temperature": 0.3,
            "messages": [{"role": "user", "content": "bonjour"}],
        }, headers=_bearer(api_key))
        assert fake_provider["temperature"] == 0.3
        assert resp.json()["usage"]["total_tokens"] == 19

    def test_stream_sse_detokenized(self, client, api_key, fake_provider,
                                    monkeypatch):
        """Mode simule (STREAM_NATIVE=false) : reponse complete puis
        decoupage SSE. Le streaming natif est couvert par test_streaming.py."""
        from app.config import get_settings
        monkeypatch.setattr(get_settings(), "stream_native", False)
        resp = client.post("/v1/chat/completions", json={
            "model": "gpt-4o",
            "stream": True,
            "messages": [{"role": "user",
                          "content": f"vire sur {IBAN} merci"}],
        }, headers=_bearer(api_key))
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")
        lines = [l for l in resp.text.split("\n") if l.startswith("data: ")]
        assert lines[-1] == "data: [DONE]"
        content = ""
        finish = None
        for line in lines[:-1]:
            payload = json.loads(line[len("data: "):])
            for choice in payload.get("choices", []):
                content += choice.get("delta", {}).get("content", "")
                finish = choice.get("finish_reason") or finish
        assert IBAN in content
        assert finish == "stop"

    def test_no_bearer_rejected(self, client, api_key):
        resp = client.post("/v1/chat/completions", json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "bonjour"}],
        })
        assert resp.status_code == 401


class TestGatewayChatAllRoles:
    def test_system_role_sanitized(self, client, api_key, monkeypatch):
        """/gateway/chat : le prompt system est assaini comme les autres."""
        captured = {}

        async def _fake(req, messages):
            captured["messages"] = messages
            return "ok"

        monkeypatch.setattr(proxy, "_forward", _fake)
        resp = client.post("/gateway/chat", json={
            "provider": "groq",
            "model": "llama-3.3-70b-versatile",
            "api_key": "gsk_fake_key_1234567890abcdefghij",
            "messages": [
                {"role": "system", "content": f"Compte interne : {IBAN}."},
                {"role": "user", "content": "bonjour"},
            ],
        }, headers={"X-SENTINEL-Key": api_key})
        assert resp.status_code == 200
        assert IBAN not in captured["messages"][0]["content"]


class TestAdminToken:
    def test_dedicated_token_replaces_hmac_key(self, client, monkeypatch):
        """Quand ADMIN_TOKEN est defini, la cle HMAC d'audit ne donne plus
        acces a /admin/keys."""
        monkeypatch.setattr(settings, "admin_token", "tok-admin-dedie-123")

        resp = client.post("/admin/keys", json={
            "client_id": "c1", "admin_token": settings.audit_hmac_key})
        assert resp.status_code == 403

        resp = client.post("/admin/keys", json={
            "client_id": "c1", "admin_token": "tok-admin-dedie-123"})
        assert resp.status_code == 200

    def test_fallback_without_dedicated_token(self, client):
        """Sans ADMIN_TOKEN, l'ancien comportement reste valide."""
        resp = client.post("/admin/keys", json={
            "client_id": "c2", "admin_token": settings.audit_hmac_key})
        assert resp.status_code == 200
