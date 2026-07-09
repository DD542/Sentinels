from __future__ import annotations
import hashlib
import hmac
import re
from ..config import get_settings
from ..detection.types import EntityType

settings = get_settings()
_KEY = bytes.fromhex(settings.vault_master_key)

# Table éphémère token -> valeur réelle (en prod : Redis chiffré, TTL court)
_REVERSE_MAP: dict[str, str] = {}

_FAKE_FIRST = ["Marc", "Julie", "Paul", "Claire", "Hugo", "Lea", "Nadia", "Anne"]
_FAKE_LAST = ["Legrand", "Moreau", "Dubois", "Girard", "Renard", "Faure", "Blanc"]
_FAKE_CITIES = ["Beaulieu", "Montvert", "Rocheval", "Clairfont", "Valbonne"]

_SEPARATORS = re.compile(r"[\s\u00A0-]")


def _prf(value: str, salt: str = "") -> int:
    """Pseudo-aléatoire déterministe dérivé de la clé maître."""
    digest = hmac.new(_KEY, (salt + value).encode(), hashlib.sha256).digest()
    return int.from_bytes(digest[:16], "big")


# ============================================================
# IBAN factice VALIDE (format préservé + clé mod-97 recalculée)
# ============================================================

def _fake_iban(original: str) -> str:
    stream = _prf(original)
    out, alnum_idx = [], 0
    for ch in original:
        if ch.isalnum():
            if alnum_idx < 4:
                out.append(ch.upper() if ch.isalpha() else ch)
            elif ch.isdigit():
                out.append(str(stream % 10))
                stream //= 10
                if stream < 10:
                    stream = _prf(original, str(alnum_idx))
            else:
                out.append(chr(ord("A") + stream % 26))
                stream //= 26
                if stream < 26:
                    stream = _prf(original, str(alnum_idx))
            alnum_idx += 1
        else:
            out.append(ch)
    fake = "".join(out)

    # Recalcule la clé de contrôle : l'IBAN factice doit être VALIDE.
    norm = _SEPARATORS.sub("", fake).upper()
    country, bban = norm[:2], norm[4:]
    numeric = "".join(str(int(c, 36)) for c in bban + country + "00")
    check_str = f"{98 - int(numeric) % 97:02d}"

    result, alnum_idx = [], 0
    for ch in fake:
        if ch.isalnum():
            if alnum_idx == 2:
                result.append(check_str[0])
            elif alnum_idx == 3:
                result.append(check_str[1])
            else:
                result.append(ch)
            alnum_idx += 1
        else:
            result.append(ch)
    return "".join(result)


def _fake_digits(original: str) -> str:
    """Chiffres factices, format préservé (téléphone, SIRET, NIR, carte)."""
    out, stream = [], _prf(original)
    for ch in original:
        if ch.isdigit():
            out.append(str(stream % 10))
            stream //= 10
            if stream < 10:
                stream = _prf(original, ch)
        else:
            out.append(ch)
    return "".join(out)


def tokenize(value: str, etype: EntityType) -> str:
    """Remplace une valeur réelle par un substitut réaliste, faux, et
    lui-même structurellement valide quand le format l'exige."""
    seed = _prf(value)

    if etype == EntityType.IBAN:
        token = _fake_iban(value)
    elif etype == EntityType.PERSON:
        token = (f"{_FAKE_FIRST[seed % len(_FAKE_FIRST)]} "
                 f"{_FAKE_LAST[(seed // 7) % len(_FAKE_LAST)]}")
    elif etype == EntityType.EMAIL:
        token = (f"{_FAKE_FIRST[seed % len(_FAKE_FIRST)].lower()}."
                 f"{_FAKE_LAST[(seed // 3) % len(_FAKE_LAST)].lower()}@exemple.fr")
    elif etype == EntityType.LOCATION:
        token = _FAKE_CITIES[seed % len(_FAKE_CITIES)]
    else:
        token = _fake_digits(value)

    _REVERSE_MAP[token] = value
    return token


def detokenize(text: str) -> str:
    """Restaure les valeurs réelles dans la réponse de l'IA."""
    for token, real in _REVERSE_MAP.items():
        text = text.replace(token, real)
    return text