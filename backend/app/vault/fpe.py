from __future__ import annotations
import hashlib
import hmac
import re
from datetime import datetime, timedelta, timezone
from difflib import SequenceMatcher

from ..config import get_settings
from ..detection.types import EntityType
from .. import db

settings = get_settings()
_KEY = bytes.fromhex(settings.vault_master_key)

_REVERSE_MAP: dict[str, tuple[str, EntityType]] = {}

_FAKE_MALE = ["Marc", "Paul", "Hugo", "Louis", "Victor", "Simon", "Denis"]
_FAKE_FEMALE = ["Julie", "Claire", "Lea", "Nadia", "Anne", "Sophie", "Manon"]
_FAKE_LAST = ["Legrand", "Moreau", "Dubois", "Girard", "Renard", "Faure", "Blanc"]
_FAKE_CITIES = ["Beaulieu", "Montvert", "Rocheval", "Clairfont", "Valbonne"]

_MALE_NAMES = {
    "jean", "pierre", "michel", "alain", "philippe", "nicolas", "christophe",
    "laurent", "francois", "stephane", "david", "pascal", "eric", "thomas",
    "julien", "olivier", "sebastien", "patrick", "vincent", "antoine",
    "alexandre", "frederic", "guillaume", "jerome", "maxime", "lucas",
    "hugo", "louis", "paul", "marc", "karim", "mohamed", "mehdi", "dylan",
    "kevin", "romain", "florian", "cedric", "bruno", "didier", "gerard",
}
_FEMALE_NAMES = {
    "marie", "nathalie", "isabelle", "sylvie", "catherine", "martine",
    "christine", "francoise", "valerie", "sandrine", "veronique", "sophie",
    "celine", "julie", "aurelie", "camille", "emma", "lea", "chloe", "manon",
    "sarah", "laura", "pauline", "claire", "anne", "lucie", "ines", "fatima",
    "amelie", "elodie", "audrey", "melanie", "stephanie", "caroline", "eva",
}

_SEPARATORS = re.compile(r"[\s\u00A0-]")
_REFORMATTABLE = {
    EntityType.IBAN, EntityType.CARD, EntityType.PHONE_FR,
    EntityType.NIR, EntityType.SIRET,
}
_FUZZY_CANDIDATE = re.compile(
    r"\b[A-Z]{2}\d{2}(?:[\s\u00A0.\-]?[A-Z0-9]){8,40}"
    r"|\b\d(?:[\s\u00A0.\-]?\d){9,25}\b",
    re.I,
)
_FUZZY_THRESHOLD = 0.72


def _prf(value: str, salt: str = "") -> int:
    digest = hmac.new(_KEY, (salt + value).encode(), hashlib.sha256).digest()
    return int.from_bytes(digest[:16], "big")


def _norm(s: str) -> str:
    return re.sub(r"[\s\u00A0.\-]", "", s).upper()


def _fake_iban(original: str) -> str:
    stream = _prf(original)
    out, alnum_idx = [], 0
    for ch in original:
        if ch.isalnum():
            if alnum_idx < 4:
                out.append(ch.upper() if ch.isalpha() else ch)
            elif ch.isdigit():
                out.append(str(stream % 10)); stream //= 10
                if stream < 10: stream = _prf(original, str(alnum_idx))
            else:
                out.append(chr(ord("A") + stream % 26)); stream //= 26
                if stream < 26: stream = _prf(original, str(alnum_idx))
            alnum_idx += 1
        else:
            out.append(ch)
    fake = "".join(out)
    norm = _SEPARATORS.sub("", fake).upper()
    country, bban = norm[:2], norm[4:]
    numeric = "".join(str(int(c, 36)) for c in bban + country + "00")
    check_str = f"{98 - int(numeric) % 97:02d}"
    result, alnum_idx = [], 0
    for ch in fake:
        if ch.isalnum():
            if alnum_idx == 2: result.append(check_str[0])
            elif alnum_idx == 3: result.append(check_str[1])
            else: result.append(ch)
            alnum_idx += 1
        else:
            result.append(ch)
    return "".join(result)


def _fake_digits(original: str) -> str:
    out, stream = [], _prf(original)
    for ch in original:
        if ch.isdigit():
            out.append(str(stream % 10)); stream //= 10
            if stream < 10: stream = _prf(original, ch)
        else:
            out.append(ch)
    return "".join(out)


def _fake_person(original: str) -> str:
    seed = _prf(original)
    first_word = original.strip().split()[0].lower() if original.strip() else ""
    if first_word in _FEMALE_NAMES:
        pool = _FAKE_FEMALE
    elif first_word in _MALE_NAMES:
        pool = _FAKE_MALE
    else:
        pool = _FAKE_MALE + _FAKE_FEMALE
    return f"{pool[seed % len(pool)]} {_FAKE_LAST[(seed // 7) % len(_FAKE_LAST)]}"


def _make_token(value: str, etype: EntityType) -> str:
    seed = _prf(value)
    if etype == EntityType.IBAN:
        return _fake_iban(value)
    if etype == EntityType.PERSON:
        return _fake_person(value)
    if etype == EntityType.EMAIL:
        return (f"{_FAKE_MALE[seed % len(_FAKE_MALE)].lower()}."
                f"{_FAKE_LAST[(seed // 3) % len(_FAKE_LAST)].lower()}@exemple.fr")
    if etype == EntityType.LOCATION:
        return _FAKE_CITIES[seed % len(_FAKE_CITIES)]
    return _fake_digits(value)


def tokenize(value: str, etype: EntityType) -> str:
    token = _make_token(value, etype)
    _REVERSE_MAP[token] = (value, etype)
    return token


async def tokenize_async(value: str, etype: EntityType) -> str:
    token = _make_token(value, etype)
    _REVERSE_MAP[token] = (value, etype)
    if db.is_enabled():
        try:
            expires = datetime.now(timezone.utc) + timedelta(hours=settings.vault_ttl_hours)
            async with db.pool().acquire() as con:
                await con.execute(
                    "INSERT INTO vault (token, cipher, entity_type, expires_at) "
                    "VALUES ($1, $2, $3, $4) "
                    "ON CONFLICT (token) DO UPDATE SET expires_at = EXCLUDED.expires_at",
                    token, db.encrypt(value), etype.value, expires,
                )
        except Exception as e:
            print(f"[SENTINEL] Écriture vault DB échouée : {type(e).__name__}: {e}")
    return token


def _fuzzy_restore(text: str, candidates: dict[str, tuple[str, EntityType]]) -> str:
    """Récupération floue : restaure les tokens corrompus par le LLM.
    Même logique que detokenize_async, factorisée pour être réutilisée
    dans les deux versions (sync et async)."""
    unmatched = [(tok, real) for tok, (real, etype) in candidates.items()
                 if etype in _REFORMATTABLE and tok not in text]
    for token, real in unmatched:
        token_n = _norm(token)
        best = None
        for m in _FUZZY_CANDIDATE.finditer(text):
            cand_n = _norm(m.group())
            if token_n[:2].isalpha() and cand_n[:2] != token_n[:2]:
                continue
            ratio = SequenceMatcher(None, cand_n, token_n).ratio()
            if ratio >= _FUZZY_THRESHOLD and (best is None or ratio > best[0]):
                best = (ratio, m.start(), m.end())
        if best:
            _, s, e = best
            text = text[:s] + real + text[e:]
    return text


def detokenize(text: str) -> str:
    """Désanonymise. Trois niveaux : exact → séparateurs → fuzzy.
    Version synchrone (cache mémoire). Utilisée partout sauf en prod
    avec base de données (detokenize_async)."""
    unmatched_structured: list[tuple[str, str]] = []

    for token, (real, etype) in _REVERSE_MAP.items():
        if token in text:
            text = text.replace(token, real)
            continue
        if etype in _REFORMATTABLE:
            alnum = [re.escape(c) for c in token if c.isalnum()]
            if not alnum:
                continue
            pattern = re.compile(r"[\s\u00A0.\-]{0,3}".join(alnum), re.IGNORECASE)
            new_text = pattern.sub(real, text)
            if new_text != text:
                text = new_text
            else:
                unmatched_structured.append((token, real))

    # Niveau 3 : récupération floue (LLM qui corrompt les chiffres)
    for token, real in unmatched_structured:
        token_n = _norm(token)
        best = None
        for m in _FUZZY_CANDIDATE.finditer(text):
            cand_n = _norm(m.group())
            if token_n[:2].isalpha() and cand_n[:2] != token_n[:2]:
                continue
            ratio = SequenceMatcher(None, cand_n, token_n).ratio()
            if ratio >= _FUZZY_THRESHOLD and (best is None or ratio > best[0]):
                best = (ratio, m.start(), m.end())
        if best:
            _, s, e = best
            text = text[:s] + real + text[e:]

    return text


async def detokenize_async(text: str) -> str:
    """Désanonymise en interrogeant cache + base."""
    candidates: dict[str, tuple[str, EntityType]] = dict(_REVERSE_MAP)

    unmatched_structured: list[tuple[str, str]] = []

    for token, (real, etype) in list(candidates.items()):
        if token in text:
            text = text.replace(token, real)
            continue
        if etype in _REFORMATTABLE:
            alnum = [re.escape(c) for c in token if c.isalnum()]
            if not alnum:
                continue
            pattern = re.compile(r"[\s\u00A0.\-]{0,3}".join(alnum), re.IGNORECASE)
            new_text = pattern.sub(real, text)
            if new_text != text:
                text = new_text
            else:
                unmatched_structured.append((token, real))

    for token, real in unmatched_structured:
        token_n = _norm(token)
        best = None
        for m in _FUZZY_CANDIDATE.finditer(text):
            cand_n = _norm(m.group())
            if token_n[:2].isalpha() and cand_n[:2] != token_n[:2]:
                continue
            ratio = SequenceMatcher(None, cand_n, token_n).ratio()
            if ratio >= _FUZZY_THRESHOLD and (best is None or ratio > best[0]):
                best = (ratio, m.start(), m.end())
        if best:
            _, s, e = best
            text = text[:s] + real + text[e:]

    return text