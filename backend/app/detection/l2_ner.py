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

# ':' et ';' exclus volontairement : apres un deux-points (format
# formulaire, "Nom: Dupont"), un mot capitalise est plus probablement
# un nom de personne qu'un verbe de debut de phrase. Constat issu du
# benchmark externe ai4privacy (texte type formulaire).
_SENTENCE_ENDINGS = ".!?\n"


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


def _plausible_person(span: str, start: int, text: str) -> bool:
    """Garde-fous anti-faux-positifs pour les personnes.

    1. Chaque mot du span doit commencer par une majuscule
       (rejette 'rediger' et autres noms communs).
    2. Un mot SEUL capitalisé en début de phrase n'est pas un indice :
       'Redige un email...' -> 'Redige' est un verbe, pas un prénom.
       Un nom seul reste accepté en milieu de phrase ('appelle Martin')."""
    words = span.strip().split()
    if not words:
        return False

    if not all(w[:1].isupper() for w in words):
        return False

    if len(words) == 1:
        prefix = text[:start].rstrip()
        sentence_initial = (not prefix) or (prefix[-1] in _SENTENCE_ENDINGS)
        if sentence_initial:
            return False

    return True


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

        if etype == EntityType.PERSON and not _plausible_person(span, r.start, text):
            continue

        findings.append(Finding(
            entity_type=etype,
            start=r.start, end=r.end,
            value=span,
            confidence=float(r.score),
            layer="L2",
            meta={"presidio_type": r.entity_type},
        ))
    return findings