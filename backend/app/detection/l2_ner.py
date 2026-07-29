from __future__ import annotations
import re
import threading
from .types import Finding, EntityType

# ============================================================
# Détection NER multilingue (L2)
#
# SENTINEL traite des prompts dans n'importe quelle langue. La stratégie :
#   * français  -> Presidio + spaCy fr (meilleure qualité, garde-fous,
#                  reconnaisseur de plaques FR) ;
#   * anglais   -> spaCy en (NER natif) ;
#   * autre     -> spaCy multilingue xx_ent_wiki_sm (PER/LOC/ORG sur ~100
#                  langues, latin ou non).
# La langue est détectée par un scoreur de mots-outils sans dépendance
# externe. Les modèles absents dégradent proprement (on retombe sur ce
# qui est installé). L1 (regex) couvre déjà emails/IBAN/cartes/secrets
# dans toutes les langues.
# ============================================================

_analyzer_fr = None          # AnalyzerEngine Presidio (fr)
_nlp_cache: dict[str, object] = {}  # modèles spaCy directs (en, xx)
_lock = threading.Lock()

PRESIDIO_MAP: dict[str, EntityType] = {
    "PERSON": EntityType.PERSON,
    "LOCATION": EntityType.LOCATION,
    "EMAIL_ADDRESS": EntityType.EMAIL,
    "PHONE_NUMBER": EntityType.PHONE_FR,
    "CREDIT_CARD": EntityType.CARD,
    "IBAN_CODE": EntityType.IBAN,
}

# Étiquettes spaCy directes -> types SENTINEL. Couvre les schémas
# OntoNotes (en : PERSON/GPE/LOC) et WikiNER (xx : PER/LOC/ORG).
SPACY_LABEL_MAP: dict[str, EntityType] = {
    "PERSON": EntityType.PERSON,
    "PER": EntityType.PERSON,
    "GPE": EntityType.LOCATION,
    "LOC": EntityType.LOCATION,
}

_SENTENCE_ENDINGS = ".!?\n"

# Mots-outils fréquents par langue : suffisent à router vers le bon modèle.
_STOPWORDS: dict[str, set[str]] = {
    "fr": {"le", "la", "les", "un", "une", "des", "et", "est", "de", "du",
           "pour", "que", "qui", "dans", "avec", "sur", "vers", "au", "aux",
           "ce", "cette", "je", "tu", "il", "elle", "nous", "vous", "ils",
           "son", "sa", "ses", "mon", "ma", "à", "par", "pas", "plus"},
    "en": {"the", "a", "an", "and", "is", "of", "for", "that", "which", "in",
           "with", "on", "to", "this", "you", "he", "she", "we", "they",
           "his", "her", "its", "my", "by", "at", "from", "as", "are", "be"},
    "es": {"el", "la", "los", "las", "un", "una", "de", "y", "es", "para",
           "que", "en", "con", "por", "su", "mi", "yo", "está", "del"},
    "de": {"der", "die", "das", "und", "ist", "von", "für", "dass", "mit",
           "auf", "zu", "ich", "du", "er", "sie", "wir", "den", "dem", "ein",
           "eine", "einen", "an", "auch", "oder", "aber", "wie", "nicht",
           "schreibe", "haben", "sein", "werden", "über"},
    "it": {"il", "la", "le", "un", "una", "di", "e", "è", "per", "che", "in",
           "con", "su", "mi", "io", "tu", "suo", "del", "della"},
    "pt": {"o", "a", "os", "as", "um", "uma", "de", "e", "é", "para", "que",
           "em", "com", "por", "seu", "eu", "está", "não"},
}

_WORD_RE = re.compile(r"[^\W\d_]+", re.UNICODE)


def detect_language(text: str) -> str:
    """Renvoie 'fr', 'en' ou 'other' (routage NER). Heuristique par
    mots-outils : robuste, instantanée, sans dépendance."""
    words = [w.lower() for w in _WORD_RE.findall(text)]
    if not words:
        return "other"
    scores = {lang: sum(1 for w in words if w in sw)
              for lang, sw in _STOPWORDS.items()}
    best = max(scores, key=scores.get)
    if scores[best] == 0:
        return "other"       # aucune langue latine reconnue -> modèle xx
    if best == "fr":
        return "fr"
    if best == "en":
        return "en"
    return "other"           # es/de/it/pt... -> modèle multilingue xx


# ------------------------------------------------------------
# Chargement paresseux des modèles
# ------------------------------------------------------------

def _build_analyzer_fr():
    """AnalyzerEngine Presidio en français (qualité + garde-fous)."""
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


# Modèle spaCy à charger selon la langue routée.
_SPACY_MODELS = {
    "en": ("en_core_web_sm", "en_core_web_lg"),
    "other": ("xx_ent_wiki_sm",),
}


def _get_spacy(kind: str):
    """Charge (une fois) le modèle spaCy direct pour 'en' ou 'other'.
    Renvoie None si aucun modèle candidat n'est installé."""
    if kind in _nlp_cache:
        return _nlp_cache[kind]
    with _lock:
        if kind in _nlp_cache:
            return _nlp_cache[kind]
        import spacy
        nlp = None
        for name in _SPACY_MODELS.get(kind, ()):
            try:
                nlp = spacy.load(name, disable=["lemmatizer", "tagger",
                                                "parser", "attribute_ruler"])
                break
            except OSError:
                continue
        _nlp_cache[kind] = nlp
        return nlp


def _get_analyzer_fr():
    global _analyzer_fr
    if _analyzer_fr is None:
        with _lock:
            if _analyzer_fr is None:
                _analyzer_fr = _build_analyzer_fr()
    return _analyzer_fr


# ------------------------------------------------------------
# Garde-fous personnes (langue-agnostiques)
# ------------------------------------------------------------

def _plausible_person(span: str, start: int, text: str) -> bool:
    """1. Chaque mot du span commence par une majuscule (rejette les noms
       communs). 2. Un mot SEUL capitalisé en début de phrase est plus
       probablement un verbe/impératif qu'un prénom."""
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


# ------------------------------------------------------------
# Chemins d'analyse
# ------------------------------------------------------------

def _scan_presidio_fr(text: str) -> list[Finding]:
    analyzer = _get_analyzer_fr()
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
            entity_type=etype, start=r.start, end=r.end, value=span,
            confidence=float(r.score), layer="L2",
            meta={"presidio_type": r.entity_type, "lang": "fr"},
        ))
    return findings


def _scan_spacy(text: str, kind: str) -> list[Finding]:
    """NER direct pour l'anglais ('en') et le multilingue ('other')."""
    nlp = _get_spacy(kind)
    if nlp is None:
        return []
    doc = nlp(text)
    findings: list[Finding] = []
    for ent in doc.ents:
        etype = SPACY_LABEL_MAP.get(ent.label_)
        if etype is None:
            continue
        # Personnes ET lieux : un mot seul capitalisé en début de phrase est
        # le plus souvent un verbe à l'impératif (Write/Escribe/Invia…), pas
        # une entité. Filtre langue-agnostique appliqué aux modèles directs.
        if etype in (EntityType.PERSON, EntityType.LOCATION) and \
                not _plausible_person(ent.text, ent.start_char, text):
            continue
        # Score fixe : les petits modèles spaCy n'exposent pas de proba.
        conf = 0.85 if etype == EntityType.PERSON else 0.6
        findings.append(Finding(
            entity_type=etype, start=ent.start_char, end=ent.end_char,
            value=ent.text, confidence=conf, layer="L2",
            meta={"spacy_label": ent.label_, "lang": kind},
        ))
    return findings


def _merge(primary: list[Finding], extra: list[Finding]) -> list[Finding]:
    """Fusionne deux listes en écartant les chevauchements de position
    (on garde l'entrée déjà présente, donc la plus prioritaire)."""
    out = list(primary)
    for f in extra:
        if not any(f.start < e.end and f.end > e.start for e in out):
            out.append(f)
    return out


def scan_sync(text: str) -> list[Finding]:
    """Analyse NER multilingue bloquante — via asyncio.to_thread.

    Français -> Presidio fr (qualité + garde-fous). Toute autre langue ->
    le modèle multilingue xx_ent_wiki_sm sert de colonne vertébrale (noms
    propres sur ~100 langues), l'anglais ajoutant le modèle en pour
    affiner. La détection de langue n'a donc jamais besoin d'être parfaite :
    une langue mal devinée reste couverte par le modèle multilingue."""
    lang = detect_language(text)

    if lang == "fr":
        findings = _scan_presidio_fr(text)
        # Repli : modèle fr absent -> on tente le multilingue.
        return findings or _scan_spacy(text, "other")

    # Non-français : le modèle multilingue est toujours consulté.
    findings = _scan_spacy(text, "other")
    if lang == "en":
        findings = _merge(findings, _scan_spacy(text, "en"))

    # Ultime repli : aucun modèle non-fr installé -> Presidio fr.
    if not findings and _get_spacy("other") is None and _get_spacy("en") is None:
        try:
            return _scan_presidio_fr(text)
        except Exception:
            return []
    return findings
