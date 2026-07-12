from __future__ import annotations
import re
from .types import Finding, EntityType

# ============================================================
# Registre officiel SWIFT : longueur exacte d'IBAN par pays
# ============================================================
IBAN_LENGTHS: dict[str, int] = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16,
    "BG": 22, "BH": 22, "BI": 27, "BR": 29, "BY": 28, "CH": 21, "CR": 22,
    "CY": 28, "CZ": 24, "DE": 22, "DJ": 27, "DK": 18, "DO": 28, "EE": 20,
    "EG": 29, "ES": 24, "FI": 18, "FK": 18, "FO": 18, "FR": 27, "GB": 22,
    "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28,
    "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30,
    "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21,
    "LY": 25, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20, "MR": 27,
    "MT": 31, "MU": 30, "NI": 28, "NL": 18, "NO": 15, "OM": 23, "PK": 24,
    "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "RU": 33,
    "SA": 24, "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27,
    "SO": 23, "ST": 25, "SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29,
    "VA": 22, "VG": 24, "XK": 20, "YE": 30,
}

IBAN_CANDIDATE = re.compile(
    r"\b([A-Za-z]{2}\d{2}(?:[\s\u00A0-]?[A-Za-z0-9]){11,40})(?![A-Za-z0-9])"
)

_SEPARATORS = re.compile(r"[\s\u00A0-]")


def _normalize_iban(raw: str) -> str:
    return _SEPARATORS.sub("", raw).upper()


# --- Validateurs algorithmiques ---

def luhn_valid(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 2:
        return False
    checksum, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def iban_valid(raw: str) -> bool:
    """Triple validation : longueur par pays (registre SWIFT),
    structure, et clé de contrôle mod-97 (ISO 7064)."""
    iban = _normalize_iban(raw)
    expected = IBAN_LENGTHS.get(iban[:2])
    if expected is None or len(iban) != expected:
        return False
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", iban):
        return False
    rearranged = iban[4:] + iban[:4]
    numeric = "".join(str(int(c, 36)) for c in rearranged)
    return int(numeric) % 97 == 1


def nir_valid(nir: str) -> bool:
    nir = nir.replace(" ", "")
    if not re.fullmatch(r"\d{15}", nir):
        return False
    number, key = nir[:13], int(nir[13:])
    return (97 - (int(number) % 97)) == key


def siret_valid(siret: str) -> bool:
    siret = siret.replace(" ", "")
    return bool(re.fullmatch(r"\d{14}", siret)) and luhn_valid(siret)


def _scan_ibans(text: str) -> list[Finding]:
    """Détection IBAN exhaustive : le match large est retréci à la
    longueur exacte du pays avant validation mod-97."""
    findings: list[Finding] = []
    for m in IBAN_CANDIDATE.finditer(text):
        raw = m.group(1)
        expected = IBAN_LENGTHS.get(raw[:2].upper())
        if expected is None:
            continue
        chars, end_idx = 0, None
        for i, ch in enumerate(raw):
            if ch.isalnum():
                chars += 1
                if chars == expected:
                    end_idx = i + 1
                    break
        if end_idx is None:
            continue
        candidate = raw[:end_idx]
        if iban_valid(candidate):
            findings.append(Finding(
                entity_type=EntityType.IBAN,
                start=m.start(1), end=m.start(1) + end_idx,
                value=candidate, confidence=1.0, layer="L1",
                meta={"country": candidate[:2].upper(), "validated": "mod97+registry"},
            ))
    return findings


# ============================================================
# Patterns SECRETS — couverture étendue des formats modernes
# ============================================================
# Chaque motif gère les préfixes composés (sk-proj-, sk-ant-api03-)
# où le tiret interne cassait l'ancien pattern générique.
_SECRET_PATTERNS: list[re.Pattern] = [
    # OpenAI : sk-, sk-proj-, sk-svcacct-, sk-admin-  (+ tirets internes)
    re.compile(r"\bsk-(?:proj|svcacct|admin|None)?-?[A-Za-z0-9_\-]{16,}\b"),
    # Anthropic : sk-ant-api03-..., sk-ant-admin01-...
    re.compile(r"\bsk-ant-[a-z0-9]+-[A-Za-z0-9_\-]{16,}\b"),
    # Groq
    re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b"),
    # AWS access key
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    # GitHub : ghp_, gho_, ghs_, ghu_, ghr_, github_pat_
    re.compile(r"\bgh[opsur]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b"),
    # Slack
    re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
    # Google API key
    re.compile(r"\bAIza[A-Za-z0-9_\-]{35}\b"),
    # Clé générique nommée : api_key=..., token: "..."
    re.compile(
        r"(?:api[_-]?key|access[_-]?token|secret[_-]?key|password)"
        r"\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?",
        re.IGNORECASE,
    ),
]

SIMPLE_PATTERNS: dict[EntityType, re.Pattern] = {
    EntityType.EMAIL: re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    EntityType.PHONE_FR: re.compile(r"\b(?:0|\+33[ ]?)[1-9](?:[ .-]?\d{2}){4}\b"),
}

PATTERNS: dict[EntityType, tuple[re.Pattern, callable]] = {
    EntityType.CARD: (re.compile(r"\b(?:\d[ -]?){13,19}\b"), luhn_valid),
    EntityType.NIR: (re.compile(r"\b[12]\s?\d{2}\s?\d{2}\s?\d{2,3}\s?\d{3}\s?\d{2}\b"), nir_valid),
    EntityType.SIRET: (re.compile(r"\b\d{3}[ ]?\d{3}[ ]?\d{3}[ ]?\d{5}\b"), siret_valid),
}


def _scan_secrets(text: str) -> list[Finding]:
    """Détecte les secrets via tous les motifs, en évitant les doublons
    de position (plusieurs motifs peuvent matcher le même secret)."""
    findings: list[Finding] = []
    seen_spans: set[tuple[int, int]] = set()
    for pattern in _SECRET_PATTERNS:
        for m in pattern.finditer(text):
            # Si le motif a un groupe de capture (clé générique), on cible le groupe
            span_start = m.start(1) if m.lastindex else m.start()
            span_end = m.end(1) if m.lastindex else m.end()
            value = m.group(1) if m.lastindex else m.group()
            key = (span_start, span_end)
            if key in seen_spans:
                continue
            # Évite un chevauchement partiel avec un secret déjà trouvé
            if any(span_start < e and span_end > s for s, e in seen_spans):
                continue
            seen_spans.add(key)
            findings.append(Finding(
                entity_type=EntityType.SECRET,
                start=span_start, end=span_end,
                value=value, confidence=0.98, layer="L1",
                meta={"kind": "secret"},
            ))
    return findings


def scan(text: str) -> list[Finding]:
    findings: list[Finding] = list(_scan_ibans(text))
    findings.extend(_scan_secrets(text))

    covered = [(f.start, f.end) for f in findings]

    def overlaps(s: int, e: int) -> bool:
        return any(s < ce and e > cs for cs, ce in covered)

    for etype, (pattern, validator) in PATTERNS.items():
        for m in pattern.finditer(text):
            if not overlaps(m.start(), m.end()) and validator(m.group()):
                findings.append(Finding(
                    entity_type=etype, start=m.start(), end=m.end(),
                    value=m.group(), confidence=1.0, layer="L1",
                    meta={"validated": True},
                ))
                covered.append((m.start(), m.end()))

    for etype, pattern in SIMPLE_PATTERNS.items():
        for m in pattern.finditer(text):
            if not overlaps(m.start(), m.end()):
                findings.append(Finding(
                    entity_type=etype, start=m.start(), end=m.end(),
                    value=m.group(), confidence=0.98, layer="L1",
                ))
                covered.append((m.start(), m.end()))

    return findings