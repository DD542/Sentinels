from __future__ import annotations
import json
import httpx
from ..config import get_settings
from .types import Finding, EntityType

settings = get_settings()

JUDGE_SYSTEM = """Tu es un juge de securite des donnees (DLP). On te donne un texte.
Reponds UNIQUEMENT en JSON strict, sans markdown, sans texte autour, au format :
{"sensitive": true/false, "entities": [{"type": "PERSON|LOCATION|SECRET|OTHER", "text": "extrait exact", "reason": "courte raison"}], "confidence": 0.0-1.0}
Regles :
- "sensitive" = true seulement si le texte contient des donnees personnelles
  identifiantes, des secrets techniques, ou des informations confidentielles.
- "text" doit etre un extrait EXACT du texte d'entree (copie caractere par caractere).
- Une question generique sans identifiant n'est PAS sensible.
- En cas de doute, sensitive = false."""

TYPE_MAP = {
    "PERSON": EntityType.PERSON,
    "LOCATION": EntityType.LOCATION,
    "SECRET": EntityType.SECRET,
}


async def judge(text: str) -> list[Finding]:
    """Arbitre local (Ollama) pour les cas ambigus. Jamais un LLM cloud :
    on ne verifie pas la sensibilite d'une donnee en l'envoyant a un tiers."""
    payload = {
        "model": settings.ollama_judge_model,
        "stream": False,
        "format": "json",
        "messages": [
            {"role": "system", "content": JUDGE_SYSTEM},
            {"role": "user", "content": text},
        ],
        "options": {"temperature": 0.0},
    }
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(
                f"{settings.ollama_base_url}/api/chat", json=payload,
            )
            resp.raise_for_status()
            content = resp.json()["message"]["content"]
            verdict = json.loads(content)
    except Exception:
        return []  # Ollama absent ou en erreur : degradation propre

    if not verdict.get("sensitive"):
        return []

    findings: list[Finding] = []
    confidence = float(verdict.get("confidence", 0.7))
    for ent in verdict.get("entities", []):
        span = str(ent.get("text", ""))
        etype = TYPE_MAP.get(str(ent.get("type", "")).upper())
        if not span or etype is None:
            continue
        pos = text.find(span)
        if pos == -1:
            continue  # le juge a hallucine un extrait : rejete
        findings.append(Finding(
            entity_type=etype,
            start=pos, end=pos + len(span),
            value=span,
            confidence=min(confidence, 0.9),  # un juge LLM ne bat jamais L1
            layer="L4",
            meta={"reason": ent.get("reason", "")},
        ))
    return findings