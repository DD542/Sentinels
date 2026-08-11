"""
Couche L4 — juge local : rattrapage de rappel sur le texte libre.

Le constat qui justifie cette couche : sur le benchmark externe, la NER
française plafonne à **34 % de F1 sur les noms de personnes**. Deux noms
sur trois passent. C'est le plafond de spaCy, pas un défaut de réglage —
Presidio brut fait le même score.

Un modèle de langue local, lui, comprend le contexte. Mesuré sur des
lignes réelles du benchmark, avec le prompt ci-dessous : 12 noms
attendus, 12 trouvés — là où l'ancien prompt en trouvait 3.

Ce qui a changé, et c'est tout le sujet : l'ancien prompt demandait un
**verdict de sensibilité** (« ce texte est-il sensible ? ») avec une
consigne explicite de répondre « non » en cas de doute. On lui demande
maintenant une **extraction** (« liste les données personnelles »). Un
juge prudent est bon pour la précision et catastrophique pour le rappel.

Le prix : une inférence coûte 5 à 25 secondes, contre 13 millisecondes
pour le reste du pipeline. Cette couche est donc **désactivée par
défaut** et s'active par client (`deep_scan`), pour les flux où le
rappel prime sur la latence.

Le modèle tourne **en local** (Ollama). On ne vérifie pas la sensibilité
d'une donnée en l'envoyant à un tiers.
"""
from __future__ import annotations
import json

import httpx

from ..config import get_settings
from .types import Finding, EntityType

settings = get_settings()

EXTRACTION_SYSTEM = """Tu extrais les donnees personnelles d'un texte, pour un outil de protection.
Reponds UNIQUEMENT en JSON strict : {"entities": [{"type": "...", "text": "..."}]}

Types : PERSON (nom ou prenom de personne), PHONE (numero de telephone),
EMAIL, LOCATION (adresse ou ville), ORG (nom d'organisation).

Regles imperatives :
- "text" est un extrait EXACT du texte fourni, copie caractere par caractere.
- Extrais CHAQUE occurrence, meme repetee.
- Un nom de personne compte meme sans prenom, meme dans un formulaire.
- N'invente rien : si tu n'es pas sur qu'une chaine figure dans le texte, omets-la.
- Ne classe PAS en PERSON un mot commun, un titre (Monsieur), ni un nom de produit."""

TYPE_MAP = {
    "PERSON": EntityType.PERSON,
    "PHONE": EntityType.PHONE_FR,
    "EMAIL": EntityType.EMAIL,
    "LOCATION": EntityType.LOCATION,
    "SECRET": EntityType.SECRET,
}

# Un juge probabiliste ne dépasse jamais une validation par somme de
# contrôle : sa confiance est plafonnée sous celle de la couche L1.
_CONFIANCE = 0.75

# Au-delà, l'inférence devient trop lente pour un usage synchrone ; on
# tronque plutôt que de faire attendre indéfiniment.
_MAX_CARACTERES = 4000


async def judge(text: str) -> list[Finding]:
    """Extrait les entités que les couches déterministes ont manquées.

    Dégradation propre : si Ollama est absent, lent ou renvoie du JSON
    invalide, on renvoie une liste vide. Une couche de rattrapage ne doit
    jamais faire échouer une analyse."""
    payload = {
        "model": settings.ollama_judge_model,
        "stream": False,
        "format": "json",
        "messages": [
            {"role": "system", "content": EXTRACTION_SYSTEM},
            {"role": "user", "content": text[:_MAX_CARACTERES]},
        ],
        "options": {"temperature": 0.0},
    }
    try:
        async with httpx.AsyncClient(timeout=settings.l4_timeout_seconds) as client:
            resp = await client.post(
                f"{settings.ollama_base_url}/api/chat", json=payload,
            )
            resp.raise_for_status()
            verdict = json.loads(resp.json()["message"]["content"])
    except Exception:
        return []  # Ollama absent, lent ou en erreur : dégradation propre

    entites = verdict.get("entities")
    if not isinstance(entites, list):
        return []

    findings: list[Finding] = []
    vus: set[tuple[str, int]] = set()
    for ent in entites:
        if not isinstance(ent, dict):
            continue
        span = str(ent.get("text") or "")
        etype = TYPE_MAP.get(str(ent.get("type") or "").upper())
        if not span or etype is None:
            continue

        # Le modèle peut halluciner un extrait : on n'accepte que ce qui
        # figure vraiment dans le texte, à sa position réelle.
        depart = 0
        while True:
            pos = text.find(span, depart)
            if pos == -1:
                break
            cle = (span, pos)
            if cle not in vus:
                vus.add(cle)
                findings.append(Finding(
                    entity_type=etype,
                    start=pos, end=pos + len(span),
                    value=span,
                    confidence=_CONFIANCE,
                    layer="L4",
                    meta={"source": "juge local"},
                ))
            depart = pos + max(1, len(span))
    return findings
