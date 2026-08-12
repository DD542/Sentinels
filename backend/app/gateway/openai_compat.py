"""
Passerelle compatible OpenAI.

Principe : n'importe quel outil configuré avec `base_url=http://<sentinel>/v1`
et une clé `sntl_…` passe par le pipeline SENTINEL avant d'atteindre le vrai
fournisseur, déterminé depuis le nom du modèle.

Deux règles gouvernent ce module, apprises d'un défaut réel : le modèle de
requête n'acceptait que `role` et `content: str`, si bien que les champs
modernes — `tools`, `response_format`, `seed`, contenu multimodal —
étaient **silencieusement abandonnés** avec un HTTP 200. L'intégration du
client cassait sans erreur, et la faute semblait venir de chez lui.

  1. **Ne jamais perdre un champ en silence.** Tout ce qui arrive est
     relayé au fournisseur, et la réponse du fournisseur est relayée au
     client telle quelle.
  2. **Ne jamais relayer un champ sans l'assainir.** Tout ce qui peut
     porter du texte utilisateur passe par la détection : contenu
     textuel, parties texte d'un contenu multimodal, arguments d'appel
     d'outil, description des outils.
"""
from __future__ import annotations
import asyncio
import json
import time
import uuid

import httpx
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict

from ..config import get_settings
from .. import auth
from .. import logs
from ..vault import fpe
from .proxy import _sanitize

settings = get_settings()
router = APIRouter()
_log = logs.get_logger("gateway")

_EMPTY_USAGE = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

# Champs que SENTINEL interprète lui-même : ils ne sont pas relayés tels
# quels. Tout le reste (top_p, seed, response_format, tools, stop,
# frequency_penalty, user…) part vers le fournisseur sans être touché.
_CHAMPS_INTERNES = {"model", "messages", "max_tokens", "temperature", "stream",
                    "stream_options"}


class Message(BaseModel):
    """Message OpenAI. `content` peut être une chaîne, une liste de
    parties (multimodal) ou nul (message porteur d'appels d'outil).
    Les champs supplémentaires — `name`, `tool_calls`, `tool_call_id` —
    sont conservés."""
    model_config = ConfigDict(extra="allow")

    role: str
    content: str | list | None = None


class ChatCompletionRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

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


# ============================================================
# Assainissement : tout ce qui porte du texte, quel que soit le champ
# ============================================================

async def _assainir_texte(texte: str, client_id: str) -> tuple[str, bool]:
    if not texte:
        return texte, False
    propre, _decisions, bloque = await _sanitize(texte, client_id)
    return propre, bloque


async def _assainir_contenu(contenu, client_id: str) -> tuple[object, bool]:
    """Contenu d'un message : chaîne, ou liste de parties multimodales.

    Les parties non textuelles (image, audio) traversent intactes : les
    inspecter n'aurait aucun sens et les altérer casserait la requête."""
    if isinstance(contenu, str):
        return await _assainir_texte(contenu, client_id)
    if isinstance(contenu, list):
        parties, bloque_global = [], False
        for partie in contenu:
            if isinstance(partie, dict) and isinstance(partie.get("text"), str):
                propre, bloque = await _assainir_texte(partie["text"], client_id)
                parties.append({**partie, "text": propre})
                bloque_global = bloque_global or bloque
            else:
                parties.append(partie)
        return parties, bloque_global
    return contenu, False


async def _assainir_appels_outil(tool_calls, client_id: str) -> tuple[list, bool]:
    """Les arguments d'un appel d'outil sont du JSON encodé en chaîne —
    et ils portent très souvent la donnée sensible : c'est là qu'un agent
    place l'IBAN ou le nom du client. Les laisser passer viderait la
    passerelle de son sens."""
    if not isinstance(tool_calls, list):
        return tool_calls, False
    sortie, bloque_global = [], False
    for appel in tool_calls:
        if not isinstance(appel, dict):
            sortie.append(appel)
            continue
        fonction = appel.get("function")
        if isinstance(fonction, dict) and isinstance(fonction.get("arguments"), str):
            propre, bloque = await _assainir_texte(fonction["arguments"], client_id)
            sortie.append({**appel, "function": {**fonction, "arguments": propre}})
            bloque_global = bloque_global or bloque
        else:
            sortie.append(appel)
    return sortie, bloque_global


async def _assainir_message(message: dict, client_id: str) -> tuple[dict, bool]:
    propre = dict(message)
    bloque = False
    if "content" in propre:
        propre["content"], b = await _assainir_contenu(propre["content"], client_id)
        bloque = bloque or b
    if propre.get("tool_calls"):
        propre["tool_calls"], b = await _assainir_appels_outil(
            propre["tool_calls"], client_id)
        bloque = bloque or b
    return propre, bloque


async def _assainir_outils(tools, client_id: str) -> tuple[object, bool]:
    """Seules les descriptions en langage naturel sont assainies : le
    schéma JSON des paramètres reste intact, sous peine de rendre l'outil
    inutilisable."""
    if not isinstance(tools, list):
        return tools, False
    sortie, bloque_global = [], False
    for outil in tools:
        if isinstance(outil, dict) and isinstance(outil.get("function"), dict):
            fonction = outil["function"]
            if isinstance(fonction.get("description"), str):
                propre, bloque = await _assainir_texte(
                    fonction["description"], client_id)
                sortie.append({**outil,
                               "function": {**fonction, "description": propre}})
                bloque_global = bloque_global or bloque
                continue
        sortie.append(outil)
    return sortie, bloque_global


# ============================================================
# Désanonymisation de la réponse
# ============================================================

async def _restaurer_message(message: dict, client_id: str) -> dict:
    """Restaure les vraies valeurs dans la réponse du fournisseur.

    Les `tool_calls` comptent autant que le texte : sans ça, l'outil du
    client recevrait un IBAN factice et virerait de l'argent nulle part."""
    sortie = dict(message)
    if isinstance(sortie.get("content"), str) and sortie["content"]:
        sortie["content"] = await fpe.detokenize_async(sortie["content"], client_id)
    appels = sortie.get("tool_calls")
    if isinstance(appels, list):
        restaures = []
        for appel in appels:
            fonction = appel.get("function") if isinstance(appel, dict) else None
            if isinstance(fonction, dict) and isinstance(fonction.get("arguments"), str):
                restaures.append({**appel, "function": {
                    **fonction,
                    "arguments": await fpe.detokenize_async(
                        fonction["arguments"], client_id)}})
            else:
                restaures.append(appel)
        sortie["tool_calls"] = restaures
    return sortie


# ============================================================
# Appel du fournisseur
# ============================================================

def _url_fournisseur(provider: str) -> str:
    if provider == "mistral":
        return f"{settings.mistral_base}/v1/chat/completions"
    if provider == "groq":
        return f"{settings.groq_base}/openai/v1/chat/completions"
    return f"{settings.openai_base}/v1/chat/completions"


def _charge_utile(provider: str, model: str, messages: list[dict],
                  max_tokens: int, temperature: float | None,
                  extras: dict | None) -> dict:
    """Construit la requête amont. Les champs non interprétés par
    SENTINEL sont relayés tels quels : c'est ce qui rend la passerelle
    réellement compatible."""
    payload = {"model": model, "max_tokens": max_tokens, "messages": messages}
    if temperature is not None:
        payload["temperature"] = temperature
    if extras and provider != "anthropic":
        # Anthropic n'utilise pas le schéma OpenAI pour `tools` ni pour
        # plusieurs paramètres : on ne relaie pas ce qu'on ne sait pas
        # traduire, plutôt que d'envoyer une requête invalide.
        payload.update({k: v for k, v in extras.items()
                        if k not in _CHAMPS_INTERNES})
    return payload


async def _forward_v1(provider: str, model: str, messages: list[dict],
                      max_tokens: int, temperature: float | None = None,
                      extras: dict | None = None) -> tuple[dict, dict]:
    """Appelle le fournisseur. Retourne (message complet, usage) — le
    message, pas seulement son texte : il peut porter des `tool_calls`."""
    api_key = _provider_key(provider)

    async with httpx.AsyncClient(timeout=60.0) as client:
        if provider == "anthropic":
            payload = _charge_utile(provider, model, messages, max_tokens,
                                    temperature, extras)
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
            texte = "".join(b.get("text", "") for b in data.get("content", []))
            return {"role": "assistant", "content": texte}, usage

        resp = await client.post(
            _url_fournisseur(provider),
            headers={"Authorization": f"Bearer {api_key}"},
            json=_charge_utile(provider, model, messages, max_tokens,
                               temperature, extras),
        )
        resp.raise_for_status()
        data = resp.json()
        choix = (data.get("choices") or [{}])[0]
        message = choix.get("message") or {"role": "assistant", "content": ""}
        usage = data.get("usage") or dict(_EMPTY_USAGE)
        return {**message, "_finish_reason": choix.get("finish_reason")}, usage


def _sse_payloads(line: str) -> dict | None:
    """Extrait l'objet JSON d'une ligne SSE `data: {...}`. None si la
    ligne n'en porte pas (commentaire, `[DONE]`, ligne vide)."""
    if not line.startswith("data:"):
        return None
    body = line[5:].strip()
    if not body or body == "[DONE]":
        return None
    try:
        return json.loads(body)
    except ValueError:
        return None


async def _stream_v1(provider: str, model: str, messages: list[dict],
                     max_tokens: int, temperature: float | None = None,
                     extras: dict | None = None):
    """Flux natif du fournisseur : produit des `(delta, finish, usage)`.
    `delta` est l'objet delta complet — il peut porter du texte ou des
    fragments d'appel d'outil. Le contenu est encore tokenisé ; la
    restauration se fait en aval, incrémentalement."""
    api_key = _provider_key(provider)

    if provider == "anthropic":
        url = f"{settings.anthropic_base}/v1/messages"
        headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01"}
    else:
        headers = {"Authorization": f"Bearer {api_key}"}
        url = _url_fournisseur(provider)

    payload = _charge_utile(provider, model, messages, max_tokens,
                            temperature, extras)
    payload["stream"] = True
    if provider != "anthropic":
        payload["stream_options"] = {"include_usage": True}

    usage = dict(_EMPTY_USAGE)
    async with httpx.AsyncClient(timeout=120.0) as client:
        async with client.stream("POST", url, headers=headers,
                                 json=payload) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                data = _sse_payloads(line)
                if data is None:
                    continue

                if provider == "anthropic":
                    kind = data.get("type")
                    if kind == "content_block_delta":
                        texte = data.get("delta", {}).get("text", "")
                        if texte:
                            yield {"content": texte}, None, None
                    elif kind == "message_start":
                        u = data.get("message", {}).get("usage", {})
                        usage["prompt_tokens"] = u.get("input_tokens", 0)
                    elif kind == "message_delta":
                        u = data.get("usage", {})
                        usage["completion_tokens"] = u.get("output_tokens", 0)
                        usage["total_tokens"] = (usage["prompt_tokens"]
                                                 + usage["completion_tokens"])
                        yield {}, data.get("delta", {}).get("stop_reason"), None
                    continue

                if data.get("usage"):
                    usage = data["usage"]
                for choix in data.get("choices", []):
                    delta = choix.get("delta") or {}
                    finish = choix.get("finish_reason")
                    if delta or finish:
                        yield delta, finish, None

    yield {}, None, usage      # dernier événement : décompte de jetons


# ============================================================
# Réponses au format OpenAI
# ============================================================

def _openai_response(model: str, message: dict, finish_reason: str = "stop",
                     usage: dict | None = None) -> dict:
    """Enveloppe un message au format ChatCompletion standard."""
    propre = {k: v for k, v in message.items() if not k.startswith("_")}
    propre.setdefault("role", "assistant")
    propre.setdefault("content", None)
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:24]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{
            "index": 0,
            "message": propre,
            "finish_reason": finish_reason,
        }],
        "usage": usage or dict(_EMPTY_USAGE),
    }


def _chunk_line(resp_id: str, created: int, model: str,
                delta: dict, finish: str | None = None) -> str:
    return "data: " + json.dumps({
        "id": resp_id, "object": "chat.completion.chunk",
        "created": created, "model": model,
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
    }, ensure_ascii=False) + "\n\n"


def _sse_response(model: str, content: str, finish_reason: str = "stop",
                  usage: dict | None = None) -> StreamingResponse:
    """Streaming simulé : la réponse est déjà complète et désanonymisée,
    elle est renvoyée en chunks SSE. Utilisé pour les refus et quand
    STREAM_NATIVE est désactivé."""
    resp_id = f"chatcmpl-{uuid.uuid4().hex[:24]}"
    created = int(time.time())

    async def gen():
        yield _chunk_line(resp_id, created, model,
                          {"role": "assistant", "content": ""})
        step = 48
        for i in range(0, len(content), step):
            yield _chunk_line(resp_id, created, model,
                              {"content": content[i:i + step]})
        yield _chunk_line(resp_id, created, model, {}, finish=finish_reason)
        if usage:
            yield "data: " + json.dumps({
                "id": resp_id, "object": "chat.completion.chunk",
                "created": created, "model": model,
                "choices": [], "usage": usage,
            }, ensure_ascii=False) + "\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


async def _native_stream_response(provider: str, model: str,
                                  messages: list[dict], max_tokens: int,
                                  temperature: float | None,
                                  client_id: str,
                                  extras: dict | None = None) -> StreamingResponse:
    """Streaming natif : les fragments du fournisseur sont désanonymisés
    au vol et réémis immédiatement.

    Les arguments d'appel d'outil arrivent eux aussi en fragments : ils
    reçoivent chacun leur propre désanonymiseur incrémental, sans quoi un
    jeton coupé entre deux fragments passerait au travers."""
    detok_texte = await fpe.make_incremental_detokenizer(client_id)
    detok_outils: dict[int, object] = {}
    resp_id = f"chatcmpl-{uuid.uuid4().hex[:24]}"
    created = int(time.time())

    async def _restaurer_delta(delta: dict) -> dict:
        sortie = dict(delta)
        if isinstance(sortie.get("content"), str) and sortie["content"]:
            sortie["content"] = detok_texte.feed(sortie["content"])
        appels = sortie.get("tool_calls")
        if isinstance(appels, list):
            restaures = []
            for appel in appels:
                fonction = appel.get("function") if isinstance(appel, dict) else None
                if isinstance(fonction, dict) and isinstance(
                        fonction.get("arguments"), str):
                    idx = appel.get("index", 0)
                    if idx not in detok_outils:
                        detok_outils[idx] = \
                            await fpe.make_incremental_detokenizer(client_id)
                    restaures.append({**appel, "function": {
                        **fonction,
                        "arguments": detok_outils[idx].feed(fonction["arguments"])}})
                else:
                    restaures.append(appel)
            sortie["tool_calls"] = restaures
        return sortie

    def _reste() -> list[dict]:
        """Vide toutes les retenues en fin de flux."""
        deltas = []
        fin_texte = detok_texte.flush()
        if fin_texte:
            deltas.append({"content": fin_texte})
        for idx, detok in detok_outils.items():
            reste = detok.flush()
            if reste:
                deltas.append({"tool_calls": [
                    {"index": idx, "function": {"arguments": reste}}]})
        return deltas

    async def gen():
        yield _chunk_line(resp_id, created, model,
                          {"role": "assistant", "content": ""})
        finish_reason = "stop"
        usage = dict(_EMPTY_USAGE)
        try:
            async for delta, finish, final_usage in _stream_v1(
                    provider, model, messages, max_tokens, temperature, extras):
                if final_usage:
                    usage = final_usage
                if finish:
                    finish_reason = finish
                if not delta:
                    continue
                restaure = await _restaurer_delta(delta)
                if any(restaure.get(k) for k in ("content", "tool_calls")):
                    yield _chunk_line(resp_id, created, model, restaure)
            for reste in _reste():
                yield _chunk_line(resp_id, created, model, reste)
        except Exception as e:
            # Le flux a déjà commencé : on ne peut plus renvoyer un code
            # HTTP d'erreur, on le signale dans le flux lui-même.
            _log.warning("flux fournisseur interrompu", extra={
                "event": "upstream_stream_error", "provider": provider,
                "error": f"{type(e).__name__}: {e}"})
            for reste in _reste():
                yield _chunk_line(resp_id, created, model, reste)
            yield _chunk_line(resp_id, created, model, {}, finish="error")
            yield "data: [DONE]\n\n"
            return

        yield _chunk_line(resp_id, created, model, {}, finish=finish_reason)
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
    """Endpoint compatible OpenAI. Tous les rôles sont assainis, tous les
    champs porteurs de texte aussi (contenu, parties multimodales,
    arguments d'outil, descriptions d'outil), et tous les champs inconnus
    sont relayés au fournisseur plutôt qu'abandonnés en silence."""
    provider = _route_provider(req.model)
    extras = {k: v for k, v in req.model_dump(exclude_unset=True).items()
              if k not in _CHAMPS_INTERNES}

    clean_messages = []
    for msg in req.messages:
        propre, bloque = await _assainir_message(
            msg.model_dump(exclude_none=False), client_id)
        if bloque:
            refus = ("Requete bloquee par SENTINEL : "
                     "contenu confidentiel detecte.")
            if req.stream:
                return _sse_response(req.model, refus,
                                     finish_reason="content_filter")
            return _openai_response(req.model,
                                    {"role": "assistant", "content": refus},
                                    finish_reason="content_filter")
        clean_messages.append(propre)

    if extras.get("tools"):
        extras["tools"], bloque = await _assainir_outils(extras["tools"], client_id)
        if bloque:
            refus = "Requete bloquee par SENTINEL : contenu confidentiel detecte."
            return _openai_response(req.model,
                                    {"role": "assistant", "content": refus},
                                    finish_reason="content_filter")

    if req.stream and settings.stream_native:
        return await _native_stream_response(provider, req.model,
                                             clean_messages, req.max_tokens,
                                             req.temperature, client_id, extras)

    try:
        message, usage = await _forward_v1(provider, req.model, clean_messages,
                                           req.max_tokens, req.temperature,
                                           extras)
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

    finish = message.pop("_finish_reason", None) or "stop"
    restaure = await _restaurer_message(message, client_id)

    if req.stream:
        return _sse_response(req.model, restaure.get("content") or "",
                             finish_reason=finish, usage=usage)
    return _openai_response(req.model, restaure, finish_reason=finish,
                            usage=usage)


# ============================================================
# /v1/models — sans lui, la passerelle est invisible
# ============================================================
#
# Open WebUI, LibreChat, Cursor et la plupart des clients appellent
# `GET /v1/models` au premier contact pour peupler leur sélecteur. Un 404
# leur fait conclure « base_url invalide » : l'utilisateur repointe son
# outil directement sur OpenAI, et SENTINEL n'est plus dans le chemin.
# Le contrôle n'est pas contourné par malveillance — il est contourné
# parce qu'il avait l'air cassé.

# Repli utilisé si le fournisseur est injoignable. Il ne sert pas de
# source de vérité : le catalogue réel est celui du fournisseur.
_CATALOGUE_REPLI: dict[str, tuple[str, ...]] = {
    "openai": ("gpt-4o", "gpt-4o-mini", "gpt-4.1", "gpt-4.1-mini", "o3-mini"),
    "anthropic": ("claude-sonnet-4-5", "claude-opus-4-1", "claude-haiku-4-5"),
    "mistral": ("mistral-large-latest", "mistral-small-latest",
                "ministral-8b-latest", "mistral-embed"),
    "groq": ("llama-3.3-70b-versatile", "llama-3.1-8b-instant"),
}

_CATALOGUE_MODELES_URL = {
    "openai": lambda: f"{settings.openai_base}/v1/models",
    "anthropic": lambda: f"{settings.anthropic_base}/v1/models",
    "mistral": lambda: f"{settings.mistral_base}/v1/models",
    "groq": lambda: f"{settings.groq_base}/openai/v1/models",
}

_CATALOGUE_TTL = 300.0                    # 5 min
_catalogue_cache: dict[str, tuple[float, list[str]]] = {}


def _reset_catalogue_cache() -> None:
    """Utilisé par les tests ; en production le cache expire seul."""
    _catalogue_cache.clear()


# Modalités que cette passerelle ne sert pas : audio et image ne passent
# pas par /v1/chat/completions ni par /v1/embeddings. Les annoncer
# ferait échouer le premier appel du client.
_MODALITES_NON_SERVIES = ("whisper", "tts", "dall-e", "sora", "playai")


def _routable(provider: str, model: str) -> bool:
    """Le modèle revient-il bien vers ce fournisseur ?

    Le routage se fait sur le préfixe du nom. Annoncer un modèle que le
    routage renverrait ailleurs (`dall-e-3` finirait chez Groq) créerait
    une erreur amont incompréhensible. On n'annonce que ce qu'on sait
    servir — quitte à annoncer moins."""
    bas = model.lower()
    if any(motif in bas for motif in _MODALITES_NON_SERVIES):
        return False
    return (_route_provider(model) == provider
            or _route_embeddings(model, strict=False) == provider)


async def _catalogue_fournisseur(provider: str) -> list[str]:
    """Modèles réellement disponibles chez ce fournisseur.

    Un catalogue figé dans le code vieillit en silence : le client voit
    un modèle retiré, ou ne voit pas celui qu'il paie. On interroge donc
    le fournisseur, avec un cache court et un repli en cas de panne."""
    maintenant = time.time()
    en_cache = _catalogue_cache.get(provider)
    if en_cache and maintenant - en_cache[0] < _CATALOGUE_TTL:
        return en_cache[1]

    try:
        cle = _provider_key(provider)
        entetes = ({"x-api-key": cle, "anthropic-version": "2023-06-01"}
                   if provider == "anthropic"
                   else {"Authorization": f"Bearer {cle}"})
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(_CATALOGUE_MODELES_URL[provider](),
                                    headers=entetes)
            resp.raise_for_status()
        noms = [str(m.get("id")) for m in (resp.json().get("data") or [])
                if m.get("id")]
    except Exception as e:
        _log.warning("catalogue fournisseur indisponible", extra={
            "event": "models_fallback", "provider": provider,
            "error": type(e).__name__})
        noms = list(_CATALOGUE_REPLI[provider])

    noms = sorted({n for n in noms if _routable(provider, n)})
    _catalogue_cache[provider] = (maintenant, noms)
    return noms


@router.get("/v1/models")
async def list_models(client_id: str = Depends(auth.verify_bearer_key)) -> dict:
    """Catalogue des modèles servis par cette passerelle.

    Seuls les fournisseurs dont la clé est configurée apparaissent : un
    modèle listé mais non servable produirait une erreur 503 au premier
    message."""
    disponibles = [p for p in _CATALOGUE_MODELES_URL
                   if _cle_configuree(p)]
    catalogues = await asyncio.gather(
        *(_catalogue_fournisseur(p) for p in disponibles),
        return_exceptions=False)

    cree = int(time.time())
    data = [{"id": nom, "object": "model", "created": cree, "owned_by": provider}
            for provider, noms in zip(disponibles, catalogues)
            for nom in noms]
    return {"object": "list", "data": data}


@router.get("/v1/models/{model_id:path}")
async def retrieve_model(model_id: str,
                         client_id: str = Depends(auth.verify_bearer_key)) -> dict:
    """Certains clients interrogent un modèle précis avant de l'utiliser."""
    provider = _route_provider(model_id)
    if not _cle_configuree(provider):
        raise HTTPException(status_code=404, detail={"error": {
            "message": f"Modele inconnu de cette passerelle : {model_id}",
            "type": "model_not_found"}})
    return {"id": model_id, "object": "model", "created": int(time.time()),
            "owned_by": provider}


def _cle_configuree(provider: str) -> bool:
    return bool({"openai": settings.openai_api_key,
                 "anthropic": settings.anthropic_api_key,
                 "mistral": settings.mistral_api_key,
                 "groq": settings.groq_api_key}.get(provider))


# ============================================================
# /v1/embeddings — le trou par lequel passaient les documents
# ============================================================
#
# Une chaîne RAG vectorise l'intégralité des documents de l'entreprise.
# Sans cet endpoint, la requête d'embedding échouait en 404 et
# l'intégrateur pointait cette seule étape directement sur OpenAI : les
# contrats, les dossiers RH et les fichiers clients partaient EN ENTIER,
# hors de toute inspection — alors même que le chat, lui, était protégé.
#
# Les vecteurs renvoyés portent le texte pseudonymisé. La recherche
# sémantique continue de fonctionner (la substitution est stable et
# déterministe : la même valeur donne toujours le même jeton), mais le
# fournisseur n'a jamais vu la donnée réelle.

class EmbeddingsRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    model: str
    input: str | list


def _route_embeddings(model: str, strict: bool = True) -> str:
    m = model.lower()
    if m.startswith(("text-embedding", "text-similarity")):
        return "openai"
    if m.startswith("mistral-embed"):
        return "mistral"
    if not strict:
        return ""
    raise HTTPException(status_code=400, detail={"error": {
        "message": (f"Modele d'embedding non supporte : {model}. "
                    "Modeles connus : text-embedding-3-small, "
                    "text-embedding-3-large, mistral-embed."),
        "type": "model_not_found"}})


@router.post("/v1/embeddings")
async def embeddings(req: EmbeddingsRequest,
                     client_id: str = Depends(auth.verify_bearer_key)):
    """Vectorise du texte **après** assainissement."""
    provider = _route_embeddings(req.model)

    entrees = req.input if isinstance(req.input, list) else [req.input]
    if not entrees:
        raise HTTPException(status_code=400, detail={"error": {
            "message": "`input` est vide", "type": "invalid_request_error"}})

    if any(not isinstance(e, str) for e in entrees):
        # Entrée déjà tokenisée en identifiants BPE : SENTINEL ne peut ni
        # la lire ni la protéger. La relayer donnerait l'illusion d'une
        # inspection qui n'a pas lieu — on refuse en le disant.
        raise HTTPException(status_code=400, detail={"error": {
            "message": ("SENTINEL n'accepte que du texte : une entree deja "
                        "convertie en identifiants de tokens ne peut pas etre "
                        "inspectee. Envoyez les chaines de caracteres."),
            "type": "invalid_request_error"}})

    propres: list[str] = []
    for texte in entrees:
        propre, bloque = await _assainir_texte(texte, client_id)
        if bloque:
            raise HTTPException(status_code=403, detail={"error": {
                "message": ("Requete bloquee par SENTINEL : contenu "
                            "confidentiel detecte."),
                "type": "content_filter"}})
        propres.append(propre)

    extras = {k: v for k, v in req.model_dump(exclude_unset=True).items()
              if k not in {"model", "input"}}
    base = settings.openai_base if provider == "openai" else settings.mistral_base
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{base}/v1/embeddings",
                headers={"Authorization": f"Bearer {_provider_key(provider)}"},
                json={"model": req.model, "input": propres, **extras})
            resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail={"error": {
            "message": f"Erreur fournisseur {provider}", "type": "upstream_error"}})
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail={"error": {
            "message": f"Fournisseur {provider} injoignable : {type(e).__name__}",
            "type": "upstream_unreachable"}})

    # Rien à désanonymiser : la réponse ne contient que des vecteurs.
    return resp.json()
