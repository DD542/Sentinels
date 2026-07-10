from __future__ import annotations
import base64
import binascii
import re
from dataclasses import dataclass

# ============================================================
# Couche L0 — Dé-obfuscation défensive.
# Objectif : révéler les données dissimulées AVANT que les couches
# de détection ne s'appliquent. On ne prétend PAS à l'exhaustivité :
# le chiffrement fort, la stéganographie et les langues non couvertes
# restent hors de portée. Le but est de relever la barre, pas de
# garantir l'imperméabilité.
# ============================================================


@dataclass
class NormalizedView:
    """Une variante dé-obfusquée du texte, avec sa provenance."""
    text: str
    technique: str   # "base64" | "hex" | "despaced" | "raw"


# --- Détection d'ingénierie sociale contre la passerelle ---
# Ces motifs ne bloquent pas l'IA : ils lèvent un drapeau d'audit.
_EVASION_PATTERNS = [
    re.compile(r"\bignore[a-z\s]{0,20}(les\s+)?(r[eè]gles|instructions|consignes)\b", re.I),
    re.compile(r"\bd[eé]sactive[a-z\s]{0,20}(la\s+)?(protection|s[eé]curit[eé]|filtre)\b", re.I),
    re.compile(r"\bcontourne[a-z\s]{0,20}(le\s+)?(filtre|syst[eè]me|scan)\b", re.I),
    re.compile(r"\b(bypass|disable|override)\b.{0,20}\b(filter|security|protection|guard)\b", re.I),
    re.compile(r"\bne\s+(scanne|filtre|bloque|analyse)\s+pas\b", re.I),
]

_B64_CANDIDATE = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}\b")
_HEX_CANDIDATE = re.compile(r"\b(?:[0-9a-fA-F]{2}[\s:]?){8,}\b")


def detect_evasion(text: str) -> list[str]:
    """Renvoie les tentatives de contournement repérées (pour l'audit)."""
    hits = []
    for pat in _EVASION_PATTERNS:
        if pat.search(text):
            hits.append(pat.pattern[:40])
    return hits


def _try_base64(text: str) -> list[str]:
    """Décode les blocs base64 plausibles ; ignore le bruit."""
    out = []
    for m in _B64_CANDIDATE.finditer(text):
        chunk = m.group()
        if len(chunk) % 4 != 0:
            continue
        try:
            decoded = base64.b64decode(chunk, validate=True)
            txt = decoded.decode("utf-8", errors="strict")
            # On ne garde que du texte imprimable et significatif
            if len(txt) >= 6 and sum(c.isprintable() for c in txt) / len(txt) > 0.9:
                out.append(txt)
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
    """Réduit les espacements excessifs entre caractères alphanumériques.
    'F R 7 6 1 0' -> 'FR7610', 's k - a b c' -> 'sk-abc'.
    On ne touche qu'aux séquences suspectes (lettres/chiffres isolés
    séparés par un seul espace/point/tiret), pas au texte normal."""
    # Séquences de type "X X X X" (caractères seuls espacés) : on recolle.
    def collapse(m):
        return re.sub(r"[\s.\-]", "", m.group())
    # Au moins 5 unités "caractère + séparateur"
    pattern = re.compile(r"(?:[A-Za-z0-9][\s.\-]){4,}[A-Za-z0-9]")
    return pattern.sub(collapse, text)


def normalized_views(text: str) -> list[NormalizedView]:
    """Produit toutes les variantes à scanner : l'original + ses
    versions dé-obfusquées. Les couches L1-L4 tourneront sur chacune."""
    views = [NormalizedView(text, "raw")]

    despaced = _despace(text)
    if despaced != text:
        views.append(NormalizedView(despaced, "despaced"))

    for decoded in _try_base64(text):
        views.append(NormalizedView(decoded, "base64"))

    for decoded in _try_hex(text):
        views.append(NormalizedView(decoded, "hex"))

    return views