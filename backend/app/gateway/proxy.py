from __future__ import annotations
import httpx
from fastapi import APIRouter
from pydantic import BaseModel

from ..config import get_settings
from ..detection.engine import DetectionEngine
from ..detection.types import Action, EntityType
from ..vault import fpe
from ..audit import chain

settings = get_settings()
router = APIRouter()
engine = DetectionEngine()


class ChatRequest(BaseModel):
    provider: str                 # "anthropic" | "openai" | "groq"
    model: str
    messages: list[dict]          # [{"role": "user", "content": "..."}]
    api_key: str                  # cle du fournisseur (jamais loggee)
    max_tokens: int = 1024


async def _sanitize(text: str) -> tuple[str, list[dict], bool]:
    """Retourne (texte nettoye, decisions, bloque_totalement)."""
    result = await engine.analyze(text)

    ip_leaks = [f for f in result.findings if f.entity_type == EntityType.IP_LEAK]
    if ip_leaks:
        leak = max(ip_leaks, key=lambda f: f.confidence)
        chain.append("BLOCK_REQUEST", "IP_LEAK",
                     str(leak.meta.get("source_doc")
                         or ",".join(leak.meta.get("source_docs", ["?"]))),
                     {"confidence": leak.confidence, **leak.meta})
        return text, [{"type": "IP_LEAK", "action": "BLOCK_REQUEST",
                       "confidence": round(leak.confidence, 3)}], True

    sanitized, decisions = text, []
    for f in sorted(result.findings, key=lambda x: x.start, reverse=True):
        action = engine.decide(f)
        if action == Action.BLOCK:
            sanitized = sanitized[:f.start] + "[BLOCKED]" + sanitized[f.end:]
        elif action == Action.TOKENIZE:
            token = fpe.tokenize(f.value, f.entity_type)
            sanitized = sanitized[:f.start] + token + sanitized[f.end:]
        entry = chain.append(action.value, f.entity_type.value,
                             f"{f.entity_type.value}:{f.start}",
                             {"confidence": f.confidence, "layer": f.layer})
        decisions.append({"type": f.entity_type.value, "action": action.value,
                          "layer": f.layer, "audit_hash": entry["hash"][:12]})
    return sanitized, decisions, False


async def _forward(req: ChatRequest, messages: list[dict]) -> str:
    """Transmet au fournisseur et extrait le texte de reponse."""
    async with httpx.AsyncClient(timeout=60.0) as client:
        if req.provider == "anthropic":
            resp = await client.post(
                f"{settings.anthropic_base}/v1/messages",
                headers={"x-api-key": req.api_key,
                         "anthropic-version": "2023-06-01"},
                json={"model": req.model, "max_tokens": req.max_tokens,
                      "messages": messages},
            )
            resp.raise_for_status()
            return "".join(b.get("text", "")
                           for b in resp.json().get("content", []))

        if req.provider == "groq":
            url = f"{settings.groq_base}/openai/v1/chat/completions"
        elif req.provider == "openai":
            url = f"{settings.openai_base}/v1/chat/completions"
        else:
            raise ValueError(f"Fournisseur inconnu : {req.provider}")

        resp = await client.post(
            url,
            headers={"Authorization": f"Bearer {req.api_key}"},
            json={"model": req.model, "max_tokens": req.max_tokens,
                  "messages": messages},
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]


@router.post("/gateway/chat")
async def chat(req: ChatRequest) -> dict:
    """Le pipeline complet : scan -> tokenisation -> fournisseur ->
    desanonymisation. L'employe recoit une reponse normale ; le
    fournisseur n'a jamais vu une seule donnee reelle."""
    all_decisions = []
    clean_messages = []

    for msg in req.messages:
        if msg.get("role") == "user":
            sanitized, decisions, blocked = await _sanitize(msg["content"])
            if blocked:
                return {"blocked": True,
                        "reason": "Contenu confidentiel de l'entreprise detecte",
                        "decisions": decisions,
                        "audit_integrity": chain.verify_integrity()}
            all_decisions.extend(decisions)
            clean_messages.append({**msg, "content": sanitized})
        else:
            clean_messages.append(msg)

    try:
        raw_answer = await _forward(req, clean_messages)
    except httpx.HTTPStatusError as e:
        return {"blocked": False, "error": f"Fournisseur : HTTP {e.response.status_code}"}
    except Exception as e:
        return {"blocked": False, "error": f"Fournisseur injoignable : {type(e).__name__}"}

    # Desanonymisation : les tokens factices redeviennent les valeurs reelles
    final_answer = fpe.detokenize(raw_answer)

    return {
        "blocked": False,
        "answer": final_answer,
        "protections_applied": all_decisions,
        "audit_integrity": chain.verify_integrity(),
    }