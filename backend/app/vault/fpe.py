from __future__ import annotations
import hashlib
import hmac
import re
from difflib import SequenceMatcher

from ..config import get_settings
from ..detection.types import EntityType

settings = get_settings()
_KEY = bytes.fromhex(settings.vault_master_key)

# Table éphémère token -> (valeur réelle, type d'entité)
# (en prod : Redis chiffré, TTL court)
_REVERSE_MAP: dict[str, tuple[str, EntityType]] = {}

# --- Prénoms factices, séparés par genre : le FPE doit préserver le
# genre pour ne pas produire de "Madame Jean Dupont" après restauration.
_FAKE_MALE = ["Marc", "Paul", "Hugo", "Louis", "Victor", "Simon", "Denis"]
_FAKE_FEMALE = ["Julie", "Claire", "Lea", "Nadia", "Anne", "Sophie", "Manon"]
_FAKE_LAST = ["Legrand", "Moreau", "Dubois", "Girard", "Renard", "Faure", "Blanc"]
_FAKE_CITIES = ["Beaulieu", "Montvert", "Rocheval", "Clairfont", "Valbonne"]

# Prénoms français courants pour la détection de genre de l'original.
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

# Types numériques/structurés que les LLM reformatent ou corrompent
# librement : désanonymisation tolérante puis récupération floue.
_REFORMATTABLE = {
    EntityType.IBAN, EntityType.CARD, EntityType.PHONE_FR,
    EntityType.NIR, EntityType.SIRET,
}

# Candidats "donnée structurée" dans une réponse LLM (pour la
# récupération floue) : 2 lettres + 2 chiffres + suite alphanum/séparateurs,
# ou longue suite de chiffres/séparateurs.
_FUZZY_CANDIDATE = re.compile(
    r"\b[A-Z]{2}\d{2}(?:[\s\u00A0.\-]?[A-Z0-9]){8,40}"
    r"|\b\d(?:[\s\u00A0.\-]?\d){9,25}\b",
    re.I,
)
_FUZZY_THRESHOLD = 0.72


def _prf(value: str, salt: str = "") -> int:
    """Pseudo-aléatoire déterministe dérivé de la clé maître."""
    digest = hmac.new(_KEY, (salt + value).encode(), hashlib.sha256).digest()
    return int.from_bytes(digest[:16], "big")


def _norm(s: str) -> str:
    return re.sub(r"[\s\u00A0.\-]", "", s).upper()


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


def _fake_person(original: str) -> str:
    """Nom factice cohérent : préserve le genre du prénom original."""
    seed = _prf(original)
    first_word = original.strip().split()[0].lower() if original.strip() else ""

    if first_word in _FEMALE_NAMES:
        pool = _FAKE_FEMALE
    elif first_word in _MALE_NAMES:
        pool = _FAKE_MALE
    else:
        pool = _FAKE_MALE + _FAKE_FEMALE  # genre inconnu : déterministe quand même

    return f"{pool[seed % len(pool)]} {_FAKE_LAST[(seed // 7) % len(_FAKE_LAST)]}"


def tokenize(value: str, etype: EntityType) -> str:
    """Remplace une valeur réelle par un substitut réaliste, faux, et
    lui-même structurellement valide quand le format l'exige."""
    seed = _prf(value)

    if etype == EntityType.IBAN:
        token = _fake_iban(value)
    elif etype == EntityType.PERSON:
        token = _fake_person(value)
    elif etype == EntityType.EMAIL:
        token = (f"{_FAKE_MALE[seed % len(_FAKE_MALE)].lower()}."
                 f"{_FAKE_LAST[(seed // 3) % len(_FAKE_LAST)].lower()}@exemple.fr")
    elif etype == EntityType.LOCATION:
        token = _FAKE_CITIES[seed % len(_FAKE_CITIES)]
    else:
        token = _fake_digits(value)

    _REVERSE_MAP[token] = (value, etype)
    return token


def detokenize(text: str) -> str:
    """Restaure les valeurs réelles dans la réponse de l'IA.

    Trois niveaux de robustesse, car les LLM ne recopient pas
    fidèlement les données structurées :
    1. Remplacement exact du token.
    2. Tolérance aux séparateurs (espaces/points/tirets insérés).
    3. Récupération floue : le LLM a corrompu des caractères du token
       (chiffres perdus, tronqué). On compare chaque candidat structuré
       de la réponse aux tokens du vault par similarité."""
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

    # --- Niveau 3 : récupération floue des tokens corrompus ---
    for token, real in unmatched_structured:
        token_n = _norm(token)
        best = None
        for m in _FUZZY_CANDIDATE.finditer(text):
            cand_n = _norm(m.group())
            if token_n[:2].isalpha() and cand_n[:2] != token_n[:2]:
                continue  # pays différent : pas le même IBAN
            ratio = SequenceMatcher(None, cand_n, token_n).ratio()
            if ratio >= _FUZZY_THRESHOLD and (best is None or ratio > best[0]):
                best = (ratio, m.start(), m.end())
        if best:
            _, s, e = best
            text = text[:s] + real + text[e:]

    return text