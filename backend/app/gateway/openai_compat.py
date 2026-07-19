from __future__ import annotations
import json
import time
import uuid
import httpx
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from ..config import get_settings
from .. import auth
from ..vault import fpe
from .proxy import _sanitize

settings = get_settings()
router = APIRouter()

_EMPTY_USAGE = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}


class Message(BaseModel):
    role: str
    content: str


class ChatCompletionRequest(BaseModel):
    model: str
    messages: list[Message]
    max_tokens: int = 1024
    temperature: float | None = None
    stream: bool = False


def _route_provider(model: str) -> str:
    """Determine le fournisseur amont a partir du nom de modele standard
    de chaque fournisseur (gpt-4o, claude-3-5-sonnet, mistral-large,
    llama-3.3-70b...)."""
    m = model.lower()
    if m.startswith(("gpt-", "o1", "o3", "o4")):
        return "openai"
    if m.startswith("claude"):
        return "anthropic"
    if m.startswith(("mistral", "codestral", "open-mixtral", "open-mistral", "ministral")):
        return "mistral"
    return "groq"  # llama, gemma, qwen, deepseek... servis en open-weights


def _provider_key(provider: str) -> str:
    key = {
        "openai": settings.openai_api_key,
        "anthropic": settings.anthropic_api_key,
        "mistral": settings.mistral_api_key,
        "groq": settings.groq_api_key,
    }[provider]
    if not key:
        raise HTTPException(
            status_code=503,
            detail={"error": {"message": f"Aucune cle {provider} configuree cote serveur (.env)",
                              "type": "provider_not_configured"}})
    return key


async def _forward_v1(provider: str, model: str, messages: list[dict],
                      max_tokens: int,
                      temperature: float | None = None) -> tuple[str, dict]:
    """Appelle le vrai fournisseur avec la cle stockee cote serveur.
    Retourne (texte, usage au format OpenAI)."""
    api_key = _provider_key(provider)

    async with httpx.AsyncClient(timeout=60.0) as client:
        if provider == "anthropic":
            payload = {"model": model, "max_tokens": max_tokens,
                       "messages": messages}
            if temperature is not None:
                payload["temperature"] = temperature
            resp = await client.post(
                f"{settings.anthropic_base}/v1/messages",
                headers={"x-api-key": api_key, "anthropic-version": "2023-06-01"},
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
            u = data.get("usage", {})
            usage = {
                "prompt_tokens": u.get("input_tokens", 0),
                "completion_tokens": u.get("output_tokens", 0),
                "total_tokens": u.get("input_tokens", 0) + u.get("output_tokens", 0),
            }
            return "".join(b.get("text", "") for b in data.get("content", [])), usage

        if provider == "mistral":
            url = f"{settings.mistral_base}/v1/chat/completions"
        elif provider == "groq":
            url = f"{settings.groq_base}/openai/v1/chat/completions"
        else:  # openai
            url = f"{settings.openai_base}/v1/chat/completions"

        payload = {"model": model, "max_tokens": max_tokens,
                   "messages": messages}
        if temperature is not None:
            payload["temperature"] = temperature
        resp = await client.post(
            url,
            headers={"Authorization": f"Bearer {api_key}"},
            json=payload,
        )
        resp.raise_for_status()
        data = resp.json()
        return (data["choices"][0]["message"]["content"],
                data.get("usage") or dict(_EMPTY_USAGE))


def _openai_response(model: str, content: str, finish_reason: str = "stop",
                     usage: dict | None = None) -> dict:
    """Enveloppe une reponse texte au format ChatCompletion standard OpenAI."""
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:24]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": finish_reason,
        }],
        "usage": usage or dict(_EMPTY_USAGE),
    }


def _sse_response(model: str, content: str, finish_reason: str = "stop",
                  usage: dict | None = None) -> StreamingResponse:
    """Streaming simule : la reponse est deja complete et desanonymisee,
    elle est renvoyee en chunks SSE au format ChatCompletion. Garantit
    qu'aucun token FPE ne peut etre coupe en deux par le decoupage, tout
    en restant compatible avec les clients OpenAI qui exigent stream=true."""
    resp_id = f"chatcmpl-{uuid.uuid4().hex[:24]}"
    created = int(time.time())

    def chunk(delta: dict, finish: str | None = None) -> str:
        return "data: " + json.dumps({
            "id": resp_id, "object": "chat.completion.chunk",
            "created": created, "model": model,
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
        }, ensure_ascii=False) + "\n\n"

    async def gen():
        yield chunk({"role": "assistant", "content": ""})
        step = 48
        for i in range(0, len(content), step):
            yield chunk({"content": content[i:i + step]})
        yield chunk({}, finish=finish_reason)
        if usage:
            yield "data: " + json.dumps({
                "id": resp_id, "object": "chat.completion.chunk",
                "created": created, "model": model,
                "choices": [], "usage": usage,
            }, ensure_ascii=False) + "\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


@router.post("/v1/chat/completions")
async def chat_completions(req: ChatCompletionRequest,
                           client_id: str = Depends(auth.verify_bearer_key)):
    """Endpoint compatible OpenAI : n'importe quel SDK/outil configure avec
    base_url=http://<sentinel>:8000/v1 et une cle sntl_... passe
    automatiquement par le pipeline de scan/audit SENTINEL avant d'atteindre
    le vrai fournisseur, determine depuis le nom du modele. Tous les roles
    (system, user, assistant) sont assainis, et la reponse est
    desanonymisee avant retour — y compris en stream."""
    provider = _route_provider(req.model)
    clean_messages = []

    for msg in req.messages:
        if msg.content:
            sanitized, decisions, blocked = await _sanitize(msg.content, client_id)
            if blocked:
                refusal = ("Requete bloquee par SENTINEL : "
                           "contenu confidentiel detecte.")
                if req.stream:
                    return _sse_response(req.model, refusal,
                                         finish_reason="content_filter")
                return _openai_response(req.model, refusal,
                                        finish_reason="content_filter")
            clean_messages.append({"role": msg.role, "content": sanitized})
        else:
            clean_messages.append({"role": msg.role, "content": msg.content})

    try:
        answer, usage = await _forward_v1(provider, req.model, clean_messages,
                                          req.max_tokens, req.temperature)
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=e.response.status_code,
            detail={"error": {"message": f"Erreur fournisseur {provider}",
                              "type": "upstream_error"}})
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=502,
            detail={"error": {"message": f"Fournisseur {provider} injoignable : {type(e).__name__}",
                              "type": "upstream_unreachable"}})

    final_answer = await fpe.detokenize_async(answer)

    if req.stream:
        return _sse_response(req.model, final_answer, usage=usage)
    return _openai_response(req.model, final_answer, usage=usage)
