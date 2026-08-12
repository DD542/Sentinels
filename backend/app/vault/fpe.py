from __future__ import annotations
import hashlib
import time
import hmac
import re
from datetime import datetime, timedelta, timezone
from difflib import SequenceMatcher

from ..config import get_settings
from ..detection.types import EntityType
from .. import db

settings = get_settings()
_KEY = bytes.fromhex(settings.vault_master_key)

# Client par défaut (usage hors passerelle, tests, outils).
DEFAULT_CLIENT = "_global"

# Vault CLOISONNÉ PAR CLIENT : client_id -> {jeton -> (valeur, type)}.
#
# Un vault partagé faisait fuiter les données d'un client chez un autre :
# la réponse d'un fournisseur destinée au client B, contenant par hasard
# un jeton du client A, se voyait restaurer avec la VRAIE valeur de A.
# Dans un outil de protection des données, c'est le pire défaut possible.
_REVERSE_MAP: dict[str, dict[str, tuple[str, EntityType]]] = {}

# Echeance de chaque jeton en memoire : client_id -> {jeton -> instant}.
#
# Sans elle, le cache ne connaissait aucune duree de vie. Deux
# consequences : il grossissait sans fin (mesure : ~1,7 Go par jour et
# par processus au debit maximal), et surtout la duree de conservation
# annoncee n'etait pas tenue — un processus demarre depuis trente jours
# restaurait encore les jetons du premier jour, alors que la politique
# promet leur suppression apres VAULT_TTL_HOURS.
_EXPIRATIONS: dict[str, dict[str, float]] = {}

# Espace des substituts. Il doit être VASTE : deux valeurs distinctes qui
# reçoivent le même jeton se corrompent mutuellement (le vault ne retient
# que la dernière) et fuitent l'une chez l'autre. Avec 7x7 prénoms et
# 7 noms — 98 combinaisons — on mesurait 3 collisions sur 20 personnes.
_FAKE_MALE = [
    "Marc", "Paul", "Hugo", "Louis", "Victor", "Simon", "Denis", "Bastien",
    "Cyprien", "Damien", "Edgar", "Fabien", "Gaspard", "Hadrien", "Ivan",
    "Joachim", "Killian", "Lorenzo", "Matheo", "Noe", "Octave", "Quentin",
    "Raphael", "Sacha", "Tristan", "Ulysse", "Valentin", "Wilfried", "Xavier",
    "Yanis", "Zacharie", "Amaury", "Brice", "Come", "Diego", "Elias",
    "Ferdinand", "Gaetan", "Hector", "Isidore", "Jocelyn", "Kilian", "Leandre",
    "Martial", "Nathanael", "Olivier", "Pacome", "Regis", "Sylvain", "Timothee",
    "Urbain", "Vianney", "Wladimir", "Yohan", "Zephyr", "Aurelien", "Bertrand",
    "Clovis", "Dorian", "Emerick", "Firmin", "Gontran", "Hilaire", "Ignace",
]
_FAKE_FEMALE = [
    "Julie", "Claire", "Lea", "Nadia", "Anne", "Sophie", "Manon", "Beatrice",
    "Capucine", "Delphine", "Eleonore", "Fanny", "Garance", "Heloise", "Iris",
    "Joanne", "Kahina", "Louise", "Margaux", "Noemie", "Ombeline", "Prune",
    "Rosalie", "Solene", "Tiphaine", "Ursule", "Violette", "Wendy", "Xaviere",
    "Yasmine", "Zoe", "Ariane", "Blandine", "Clemence", "Domitille", "Elsa",
    "Flavie", "Gwenaelle", "Hortense", "Ines", "Jeanne", "Katia", "Lucile",
    "Maelys", "Nine", "Orianne", "Peggy", "Roxane", "Sidonie", "Thais",
    "Ulrike", "Valentine", "Wanda", "Ysaline", "Zelie", "Apolline", "Berenice",
    "Coline", "Douceline", "Eugenie", "Faustine", "Gaelle", "Honorine", "Irma",
]
_FAKE_LAST = [
    "Legrand", "Moreau", "Dubois", "Girard", "Renard", "Faure", "Blanc",
    "Arnaud", "Berger", "Chevalier", "Dupuis", "Etienne", "Fontaine", "Gauthier",
    "Herve", "Imbert", "Jacquet", "Klein", "Lemoine", "Marchand", "Noel",
    "Ollivier", "Perrot", "Quesnel", "Rivoire", "Salomon", "Texier", "Ughetto",
    "Vasseur", "Weber", "Ximenes", "Yvon", "Zeller", "Aubert", "Bonnet",
    "Colin", "Delaunay", "Evrard", "Ferrand", "Gilbert", "Huet", "Isnard",
    "Joubert", "Kessler", "Lacroix", "Mallet", "Navarro", "Ozanne", "Peltier",
    "Quintin", "Rossignol", "Sauvage", "Thibault", "Urbain", "Verdier", "Wagner",
    "Xavier", "Yvard", "Zimmer", "Alliot", "Baudry", "Cartier", "Doucet",
    "Esteve", "Flamand", "Grangier", "Hamon", "Ivanoff", "Jourdain", "Kervella",
    "Lanvin", "Mounier", "Neveu", "Orsini", "Pasquier", "Rambaud", "Sorel",
    "Turpin", "Vaillant", "Wibaux", "Yzerman", "Zamora",
]
_FAKE_CITIES = [
    "Beaulieu", "Montvert", "Rocheval", "Clairfont", "Valbonne", "Aubercourt",
    "Bellerive", "Chandreuil", "Doncelles", "Ecuvillon", "Fontenoy", "Grandpre",
    "Hautrive", "Ivrezel", "Joncherey", "Larmont", "Maussac", "Noireval",
    "Ormessan", "Pierrelac", "Quintenas", "Roquebrune", "Sauveterre", "Tourmens",
    "Ussanges", "Vaucresson", "Wancourt", "Yvrandes", "Zellenberg", "Argenteil",
    "Brumecourt", "Chastelier", "Douvrenne", "Estampes", "Framboisy", "Gouvieux",
]

# Un jeton en collision corrompt DEUX valeurs : on redérive tant que le
# jeton est déjà pris par une autre valeur du même client.
_MAX_TENTATIVES = 64

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


def _fake_iban(original: str, tentative: int = 0) -> str:
    stream = _prf(original, f"i{tentative}")
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


def _client_map(client_id: str) -> dict[str, tuple[str, EntityType]]:
    """Vault d'un client. Aucun autre client n'y a accès."""
    return _REVERSE_MAP.setdefault(client_id, {})


def _client_expirations(client_id: str) -> dict[str, float]:
    return _EXPIRATIONS.setdefault(client_id, {})


def _noter(client_id: str, token: str, value: str, etype: EntityType) -> None:
    """Enregistre un jeton et son échéance."""
    _client_map(client_id)[token] = (value, etype)
    _client_expirations(client_id)[token] = (
        time.time() + settings.vault_ttl_hours * 3600)


def _candidats_memoire(client_id: str) -> dict[str, tuple[str, EntityType]]:
    """Jetons du client **encore valides**.

    Un jeton périmé ne doit plus rien restaurer, même si la passe de
    maintenance ne l'a pas encore évincé : la durée de conservation est
    une promesse, pas une intention."""
    maintenant = time.time()
    echeances = _client_expirations(client_id)
    return {jeton: valeur
            for jeton, valeur in _client_map(client_id).items()
            # Absence d'échéance : entrée posée directement (tests, outils).
            if echeances.get(jeton, float("inf")) > maintenant}


def _fake_digits(original: str, tentative: int = 0) -> str:
    out, stream = [], _prf(original, f"d{tentative}")
    for ch in original:
        if ch.isdigit():
            out.append(str(stream % 10)); stream //= 10
            if stream < 10: stream = _prf(original, ch)
        else:
            out.append(ch)
    return "".join(out)


def _fake_person(original: str, tentative: int = 0) -> str:
    seed = _prf(original, f"p{tentative}")
    first_word = original.strip().split()[0].lower() if original.strip() else ""
    if first_word in _FEMALE_NAMES:
        pool = _FAKE_FEMALE
    elif first_word in _MALE_NAMES:
        pool = _FAKE_MALE
    else:
        pool = _FAKE_MALE + _FAKE_FEMALE
    return f"{pool[seed % len(pool)]} {_FAKE_LAST[(seed // 7) % len(_FAKE_LAST)]}"


def _deriver(value: str, etype: EntityType, tentative: int) -> str:
    seed = _prf(value, f"t{tentative}")
    if etype == EntityType.IBAN:
        return _fake_iban(value, tentative)
    if etype == EntityType.PERSON:
        return _fake_person(value, tentative)
    if etype == EntityType.EMAIL:
        return (f"{_FAKE_MALE[seed % len(_FAKE_MALE)].lower()}."
                f"{_FAKE_LAST[(seed // 3) % len(_FAKE_LAST)].lower()}@exemple.fr")
    if etype == EntityType.LOCATION:
        return _FAKE_CITIES[seed % len(_FAKE_CITIES)]
    return _fake_digits(value, tentative)


def _make_token(value: str, etype: EntityType,
                client_id: str = DEFAULT_CLIENT) -> str:
    """Substitut du client, garanti sans collision dans SON vault.

    La dérivation reste déterministe — la même valeur donne le même
    jeton — mais si ce jeton est déjà pris par une AUTRE valeur, on
    redérive. Sans cette boucle, deux personnes distinctes recevaient le
    même substitut : le vault ne gardait que la dernière, et la première
    se voyait restaurer avec la donnée de la seconde."""
    vault = _client_map(client_id)
    for tentative in range(_MAX_TENTATIVES):
        token = _deriver(value, etype, tentative)
        occupant = vault.get(token)
        if occupant is None or occupant[0] == value:
            return token
    # Espace saturé pour ce client : on discrimine par un suffixe stable
    # plutôt que d'accepter une collision.
    return f"{_deriver(value, etype, 0)} {_prf(value, 'suffixe') % 1000:03d}"


def tokenize(value: str, etype: EntityType,
             client_id: str = DEFAULT_CLIENT) -> str:
    token = _make_token(value, etype, client_id)
    _noter(client_id, token, value, etype)
    return token


async def tokenize_async(value: str, etype: EntityType,
                         client_id: str = DEFAULT_CLIENT) -> str:
    token = _make_token(value, etype, client_id)
    _noter(client_id, token, value, etype)
    if db.is_enabled():
        try:
            expires = datetime.now(timezone.utc) + timedelta(hours=settings.vault_ttl_hours)
            async with db.pool().acquire() as con:
                await con.execute(
                    "INSERT INTO vault "
                    "(client_id, token, cipher, entity_type, expires_at) "
                    "VALUES ($1, $2, $3, $4, $5) "
                    "ON CONFLICT (client_id, token) DO UPDATE "
                    "SET expires_at = EXCLUDED.expires_at",
                    client_id, token, db.encrypt(value, client_id),
                    etype.value, expires,
                )
        except Exception as e:
            from .. import logs
            logs.get_logger("vault").warning(
                "ecriture vault DB echouee",
                extra={"event": "db_error", "op": "insert_token",
                       "error": f"{type(e).__name__}: {e}"})
    return token


# Garde-fou mémoire : nombre max de tokens rechargés depuis la base pour
# une désanonymisation. Le TTL (vault_ttl_hours) borne déjà la table ;
# cette limite protège d'un pic de trafic exceptionnel.
_DB_CANDIDATE_LIMIT = 5000


async def _db_candidates(client_id: str = DEFAULT_CLIENT) -> dict[str, tuple[str, EntityType]]:
    """Tokens encore valides en base.

    Indispensable : le cache mémoire est LOCAL au process. Sans cette
    relecture, un redémarrage — ou un simple déploiement multi-workers,
    où la tokenisation et la réponse ne tombent pas sur le même process —
    renverrait à l'employé le token factice au lieu de sa vraie valeur."""
    out: dict[str, tuple[str, EntityType]] = {}
    if not db.is_enabled():
        return out
    try:
        async with db.pool().acquire() as con:
            rows = await con.fetch(
                "SELECT token, cipher, entity_type FROM vault "
                "WHERE client_id = $1 AND expires_at > now() "
                "ORDER BY created_at DESC LIMIT $2",
                client_id, _DB_CANDIDATE_LIMIT)
        for r in rows:
            real = db.decrypt(r["cipher"], client_id)
            if real is None:
                # Clé changée, ou ligne chiffrée pour un AUTRE client :
                # dans les deux cas, on n'en tire rien. C'est ce
                # cloisonnement cryptographique qui rend une erreur de
                # filtrage SQL inoffensive.
                continue
            try:
                out[r["token"]] = (real, EntityType(r["entity_type"]))
            except ValueError:
                continue          # type inconnu (schéma plus récent)
    except Exception as e:
        from .. import logs
        logs.get_logger("vault").warning(
            "relecture vault DB echouee",
            extra={"event": "db_error", "op": "load_candidates",
                   "error": f"{type(e).__name__}: {e}"})
    return out


def _evincer_memoire() -> int:
    """Retire du cache les jetons périmés. Sans cette éviction, le cache
    croît indéfiniment : ~1,7 Go par jour et par processus au débit
    maximal mesuré."""
    maintenant = time.time()
    evinces = 0
    for client_id, echeances in list(_EXPIRATIONS.items()):
        perimes = [j for j, fin in echeances.items() if fin <= maintenant]
        if not perimes:
            continue
        vault = _REVERSE_MAP.get(client_id, {})
        for jeton in perimes:
            echeances.pop(jeton, None)
            vault.pop(jeton, None)
        evinces += len(perimes)

        # `pop` retire l'entrée mais ne rend pas la table de hachage :
        # un dict qui a contenu 20 000 clés en occupe encore 0,8 Mo une
        # fois vidé. Reconstruire le libère réellement. On ne le fait que
        # si la purge a emporté au moins la moitié — sinon la recopie
        # coûterait plus qu'elle ne rapporte.
        if len(perimes) >= len(vault):
            _REVERSE_MAP[client_id] = dict(vault)
            _EXPIRATIONS[client_id] = dict(echeances)
    return evinces


async def purge_expired_detail() -> dict[str, int]:
    """Applique réellement la durée de conservation, **des deux côtés** :
    éviction du cache mémoire et suppression des lignes en base. Sans ça,
    `expires_at` ne serait qu'une intention (et la politique de rétention
    annoncée, inexacte).

    Les deux comptages sont rapportés séparément parce qu'ils ne
    répondent pas de la même chose : la base est partagée, le cache est
    local à chaque processus."""
    evinces = _evincer_memoire()
    if evinces:
        from .. import logs
        logs.get_logger("vault").info(
            "jetons evinces du cache", extra={
                "event": "vault_cache_evict", "evicted": evinces})
    return {"cache_evicted": evinces, "rows_deleted": await _purger_base()}


async def purge_expired() -> int:
    """Nombre de lignes supprimées en base. Voir `purge_expired_detail`."""
    return (await purge_expired_detail())["rows_deleted"]


async def _purger_base() -> int:
    if not db.is_enabled():
        return 0
    try:
        async with db.pool().acquire() as con:
            result = await con.execute(
                "DELETE FROM vault WHERE expires_at <= now()")
        deleted = int(result.split()[-1]) if result else 0
        if deleted:
            from .. import logs
            logs.get_logger("vault").info(
                "tokens expires purges",
                extra={"event": "vault_purge", "deleted": deleted})
        return deleted
    except Exception as e:
        from .. import logs
        logs.get_logger("vault").warning(
            "purge vault echouee",
            extra={"event": "db_error", "op": "purge_expired",
                   "error": f"{type(e).__name__}: {e}"})
        return 0


class IncrementalDetokenizer:
    """Désanonymisation au fil de l'eau, pour le streaming.

    Le problème : un jeton FPE peut être **coupé entre deux chunks**
    (« FR2473 » puis « 620249543… »). Remplacer chunk par chunk le
    manquerait et l'employé recevrait la valeur factice.

    La solution : une fenêtre de retenue. On accumule le texte, on
    désanonymise l'ensemble, puis on n'émet que ce qui ne peut plus
    faire partie d'un jeton en cours d'arrivée — c'est-à-dire tout sauf
    les `keep` derniers caractères. Un jeton incomplet est forcément un
    suffixe plus court que le plus long jeton connu : il reste donc
    entièrement dans la retenue jusqu'à être complet.

    Compromis assumé : la **récupération floue** (jeton corrompu par le
    modèle) n'opère pas en streaming — elle a besoin du texte entier, et
    on ne peut pas reprendre un texte déjà émis. Les correspondances
    exacte et tolérante aux séparateurs, elles, fonctionnent."""

    # Marge au-delà du plus long jeton : le modèle peut insérer des
    # séparateurs (« FR76 1010 7001 »), ce qui allonge la forme reçue.
    _SEPARATOR_SLACK = 3
    _MAX_KEEP = 512

    def __init__(self, candidates: dict[str, tuple[str, EntityType]]):
        self._candidates = candidates
        self._buffer = ""
        longest = max((len(t) for t in candidates), default=0)
        self._keep = min(longest * self._SEPARATOR_SLACK, self._MAX_KEEP)

    def feed(self, chunk: str) -> str:
        """Absorbe un fragment ; renvoie ce qui peut être émis sans risque
        de couper un jeton (éventuellement une chaîne vide)."""
        if not self._candidates:
            return chunk                     # rien à restaurer : passe-plat
        self._buffer += chunk
        if len(self._buffer) <= self._keep:
            return ""
        restored = self._restore(self._buffer)
        if len(restored) <= self._keep:
            self._buffer = restored
            return ""
        emit, self._buffer = restored[:-self._keep], restored[-self._keep:]
        return emit

    def flush(self) -> str:
        """Vide la retenue en fin de flux, récupération floue comprise :
        à ce stade plus rien n'arrive, le contexte est complet."""
        if not self._buffer:
            return ""
        remaining = _fuzzy_restore(self._restore(self._buffer),
                                   self._candidates)
        self._buffer = ""
        return remaining

    def _restore(self, text: str) -> str:
        """Niveaux 1 et 2 : correspondance exacte, puis tolérante aux
        séparateurs. Idempotent — une valeur déjà restaurée n'est pas un
        jeton, elle traverse les passes suivantes sans changer."""
        for token, (real, etype) in self._candidates.items():
            if token in text:
                text = text.replace(token, real)
                continue
            if etype in _REFORMATTABLE:
                alnum = [re.escape(c) for c in token if c.isalnum()]
                if not alnum:
                    continue
                pattern = re.compile(
                    r"[\s .\-]{0,3}".join(alnum), re.IGNORECASE)
                text = pattern.sub(real, text)
        return text


async def make_incremental_detokenizer(
        client_id: str = DEFAULT_CLIENT) -> IncrementalDetokenizer:
    """Désanonymiseur de flux pour UN client : cache mémoire local +
    base (autres workers, redémarrages). Jamais les jetons d'un autre."""
    candidates = await _db_candidates(client_id)
    candidates.update(_candidats_memoire(client_id))
    return IncrementalDetokenizer(candidates)


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


def detokenize(text: str, client_id: str = DEFAULT_CLIENT) -> str:
    """Désanonymise. Trois niveaux : exact → séparateurs → fuzzy.
    Version synchrone (cache mémoire). Utilisée partout sauf en prod
    avec base de données (detokenize_async)."""
    unmatched_structured: list[tuple[str, str]] = []

    for token, (real, etype) in _candidats_memoire(client_id).items():
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


async def detokenize_async(text: str,
                           client_id: str = DEFAULT_CLIENT) -> str:
    """Désanonymise en interrogeant cache mémoire ET base.

    Le cache local prime (il est toujours à jour) ; la base couvre les
    tokens créés par un autre process ou avant un redémarrage."""
    candidates: dict[str, tuple[str, EntityType]] = await _db_candidates(client_id)
    candidates.update(_candidats_memoire(client_id))

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