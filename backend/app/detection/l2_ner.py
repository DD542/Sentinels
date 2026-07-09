from __future__ import annotations
import threading
from .types import Finding, EntityType

_analyzer = None
_lock = threading.Lock()

PRESIDIO_MAP: dict[str, EntityType] = {
    "PERSON": EntityType.PERSON,
    "LOCATION": EntityType.LOCATION,
    "EMAIL_ADDRESS": EntityType.EMAIL,
    "PHONE_NUMBER": EntityType.PHONE_FR,
    "CREDIT_CARD": EntityType.CARD,
    "IBAN_CODE": EntityType.IBAN,
}


def _build_analyzer():
    """Construit l'AnalyzerEngine Presidio en français, une seule fois."""
    from presidio_analyzer import (
        AnalyzerEngine, Pattern, PatternRecognizer, RecognizerRegistry,
    )
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    nlp_config = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "fr", "model_name": "fr_core_news_lg"}],
    }
    nlp_engine = NlpEngineProvider(nlp_configuration=nlp_config).create_engine()

    registry = RecognizerRegistry(supported_languages=["fr"])
    registry.load_predefined_recognizers(languages=["fr"], nlp_engine=nlp_engine)

    plaque = PatternRecognizer(
        supported_entity="FR_PLATE",
        supported_language="fr",
        patterns=[Pattern("plaque_siv", r"\b[A-Z]{2}-\d{3}-[A-Z]{2}\b", 0.4)],
        context=["vehicule", "véhicule", "immatriculation", "plaque", "voiture"],
    )
    registry.add_recognizer(plaque)

    return AnalyzerEngine(
        nlp_engine=nlp_engine,
        registry=registry,
        supported_languages=["fr"],
    )


def _get_analyzer():
    global _analyzer
    if _analyzer is None:
        with _lock:
            if _analyzer is None:
                _analyzer = _build_analyzer()
    return _analyzer


def _plausible_person(span: str) -> bool:
    """Garde-fou anti-faux-positif : un nom de personne commence par une
    majuscule. Rejette les verbes/noms communs que le NER prend pour des
    personnes (ex : 'rediger')."""
    words = span.strip().split()
    if not words:
        return False
    capitalized = sum(1 for w in words if w[:1].isupper())
    return capitalized >= max(1, len(words) - 1) and words[0][:1].isupper()


def scan_sync(text: str) -> list[Finding]:
    """Analyse NER bloquante — à appeler via asyncio.to_thread."""
    analyzer = _get_analyzer()
    results = analyzer.analyze(text=text, language="fr")

    findings: list[Finding] = []
    for r in results:
        etype = PRESIDIO_MAP.get(r.entity_type)
        if etype is None:
            continue
        span = text[r.start:r.end]

        if etype == EntityType.PERSON and not _plausible_person(span):
            continue  # 'rediger' et consorts : rejetés

        findings.append(Finding(
            entity_type=etype,
            start=r.start, end=r.end,
            value=span,
            confidence=float(r.score),
            layer="L2",
            meta={"presidio_type": r.entity_type},
        ))
    return findings