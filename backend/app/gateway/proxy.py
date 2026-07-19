from __future__ import annotations
import httpx
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ..config import get_settings
from ..detection.engine import DetectionEngine
from ..detection.types import Action, EntityType
from ..vault import fpe
from ..audit import chain
from .. import events
from .. import auth

settings = get_settings()
router = APIRouter()
engine = DetectionEngine()


class ChatRequest(BaseModel):
    provider: str
    model: str
    messages: list[dict]
    api_key: str
    max_tokens: int = 1024


async def _sanitize(text: str, client_id: str) -> tuple[str, list[dict], bool]:
    result = await engine.analyze(text)
    await events.publish({"kind": "scan", "length": len(text)})

    if result.evasion_attempts:
        entry = await chain.append_async("EVASION_ATTEMPT", "GATEWAY", client_id,
                                         {"patterns": result.evasion_attempts})
        await events.publish({
            "kind": "decision", "action": "EVASION_FLAG",
            "entity_type": "EVASION", "layer": "L0",
            "confidence": 1.0, "audit_hash": entry["hash"][:12],
        })

    ip_leaks = [f for f in result.findings if f.entity_type == EntityType.IP_LEAK]
    if ip_leaks:
        leak = max(ip_leaks, key=lambda f: f.confidence)
        entry = await chain.append_async(
            "BLOCK_REQUEST", "IP_LEAK",
            str(leak.meta.get("source_doc")
                or ",".join(leak.meta.get("source_docs", ["?"]))),
            {"confidence": leak.confidence, **leak.meta})
        await events.publish({
            "kind": "decision", "action": "BLOCK_REQUEST",
            "entity_type": "IP_LEAK", "layer": "L3",
            "confidence": round(leak.confidence, 3),
            "audit_hash": entry["hash"][:12],
        })
        return text, [{"type": "IP_LEAK", "action": "BLOCK_REQUEST",
                       "confidence": round(leak.confidence, 3)}], True

    sanitized = text
    decisions = []
    positional = [f for f in result.findings if "obfuscation" not in f.meta]
    by_value = [f for f in result.findings if "obfuscation" in f.meta]

    for f in sorted(positional, key=lambda x: x.start, reverse=True):
        action = engine.decide(f)
        if action == Action.BLOCK:
            sanitized = sanitized[:f.start] + "[BLOCKED]" + sanitized[f.end:]
        elif action == Action.TOKENIZE:
            token = await fpe.tokenize_async(f.value, f.entity_type)
            sanitized = sanitized[:f.start] + token + sanitized[f.end:]
        entry = await chain.append_async(
            action.value, f.entity_type.value,
            f"{f.entity_type.value}:{f.start}",
            {"confidence": f.confidence, "layer": f.layer})
        decisions.append({"type": f.entity_type.value, "action": action.value,
                          "layer": f.layer, "audit_hash": entry["hash"][:12]})
        await events.publish({
            "kind": "decision", "action": action.value,
            "entity_type": f.entity_type.value, "layer": f.layer,
            "confidence": round(f.confidence, 3),
            "audit_hash": entry["hash"][:12],
        })

    for f in by_value:
        entry = await chain.append_async(
            "BLOCK", f.entity_type.value, f"{f.entity_type.value}:obf",
            {"confidence": f.confidence, "layer": f.layer,
             "obfuscation": f.meta.get("obfuscation")})
        decisions.append({"type": f.entity_type.value, "action": "BLOCK",
                          "layer": f.layer, "obfuscation": f.meta.get("obfuscation"),
                          "audit_hash": entry["hash"][:12]})
        await events.publish({
            "kind": "decision", "action": "BLOCK",
            "entity_type": f.entity_type.value, "layer": f.layer,
            "confidence": round(f.confidence, 3),
            "audit_hash": entry["hash"][:12],
        })
    if by_value:
        sanitized += "\n[Contenu dissimulé détecté et retiré par SENTINEL]"

    return sanitized, decisions, False


async def _forward(req: ChatRequest, messages: list[dict]) -> str:
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
async def chat(req: ChatRequest,
               client_id: str = Depends(auth.verify_key)) -> dict:
    """Pipeline complet protégé par clé SENTINEL : scan -> tokenisation
    -> fournisseur -> désanonymisation."""
    all_decisions = []
    clean_messages = []

    if len(req.api_key) < 20 or " " in req.api_key:
        return {"blocked": False,
                "error": "Cle API fournisseur invalide ou placeholder non remplace"}

    # Tous les roles sont assainis (user, system, assistant) : un prompt
    # system ou un historique recolle peut contenir autant de donnees
    # sensibles qu'un message utilisateur.
    for msg in req.messages:
        if isinstance(msg.get("content"), str) and msg["content"]:
            sanitized, decisions, blocked = await _sanitize(msg["content"], client_id)
            if blocked:
                return {"blocked": True,
                        "reason": "Contenu confidentiel de l'entreprise detecte",
                        "decisions": decisions,
                        "audit_integrity": await chain.verify_integrity_async()}
            all_decisions.extend(decisions)
            clean_messages.append({**msg, "content": sanitized})
        else:
            clean_messages.append(msg)

    await events.publish({"kind": "provider", "provider": req.provider})

    try:
        raw_answer = await _forward(req, clean_messages)
    except httpx.HTTPStatusError as e:
        return {"blocked": False,
                "error": f"Fournisseur : HTTP {e.response.status_code}"}
    except Exception as e:
        return {"blocked": False,
                "error": f"Fournisseur injoignable : {type(e).__name__}"}

    final_answer = await fpe.detokenize_async(raw_answer)

    return {
        "blocked": False,
        "answer": final_answer,
        "protections_applied": all_decisions,
        "audit_integrity": await chain.verify_integrity_async(),
    }