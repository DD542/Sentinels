from __future__ import annotations
import base64
import binascii
import re
from dataclasses import dataclass


@dataclass
class NormalizedView:
    text: str
    technique: str


_EVASION_PATTERNS = [
    re.compile(r"\bignore[a-z\s]{0,20}(les\s+)?(r[eè]gles|instructions|consignes)\b", re.I),
    re.compile(r"\bd[eé]sactive[a-z\s]{0,20}(la\s+)?(protection|s[eé]curit[eé]|filtre)\b", re.I),
    re.compile(r"\bcontourne[a-z\s]{0,20}(le\s+)?(filtre|syst[eè]me|scan)\b", re.I),
    re.compile(r"\b(bypass|disable|override)\b.{0,20}\b(filter|security|protection|guard)\b", re.I),
    re.compile(r"\bne\s+(scanne|filtre|bloque|analyse)\s+pas\b", re.I),
]

_B64_CANDIDATE = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}")
_HEX_CANDIDATE = re.compile(r"\b(?:[0-9a-fA-F]{2}[\s:]?){8,}\b")


def detect_evasion(text: str) -> list[str]:
    hits = []
    for pat in _EVASION_PATTERNS:
        if pat.search(text):
            hits.append(pat.pattern[:40])
    return hits


def _try_base64(text: str) -> list[str]:
    """Décode les blocs base64 plausibles. On essaie plusieurs longueurs
    de padding car le \\b de la regex peut couper le = final."""
    out = []
    for m in _B64_CANDIDATE.finditer(text):
        chunk = m.group().rstrip("=")
        # On tente d'ajouter le padding manquant (0 à 2 signes =)
        for pad in range(3):
            candidate = chunk + "=" * pad
            if len(candidate) % 4 != 0:
                continue
            try:
                decoded = base64.b64decode(candidate, validate=True)
                txt = decoded.decode("utf-8", errors="strict")
                txt = txt.strip().strip("\r\n\x00")
                if len(txt) >= 6 and sum(c.isprintable() for c in txt) / len(txt) > 0.9:
                    out.append(txt)
                    break
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
    return out


def _try_hex(text: str) -> list[str]:
    out = []
    for m in _HEX_CANDIDATE.finditer(text):
        raw = re.sub(r"[\s:]", "", m.group())
        if len(raw) % 2 != 0:
            continue
        try:
            decoded = bytes.fromhex(raw).decode("utf-8", errors="strict")
            if len(decoded) >= 6 and sum(c.isprintable() for c in decoded) / len(decoded) > 0.9:
                out.append(decoded)
        except (ValueError, UnicodeDecodeError):
            continue
    return out


def _despace(text: str) -> str:
    def collapse(m):
        return re.sub(r"[\s.\-]", "", m.group())
    pattern = re.compile(r"(?:[A-Za-z0-9][\s.\-]){4,}[A-Za-z0-9]")
    return pattern.sub(collapse, text)


def normalized_views(text: str) -> list[NormalizedView]:
    views = [NormalizedView(text, "raw")]

    despaced = _despace(text)
    if despaced != text:
        views.append(NormalizedView(despaced, "despaced"))

    for decoded in _try_base64(text):
        views.append(NormalizedView(decoded, "base64"))

    for decoded in _try_hex(text):
        views.append(NormalizedView(decoded, "hex"))

    return views