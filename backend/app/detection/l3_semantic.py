from __future__ import annotations
import hashlib
import re
import threading
from ..config import get_settings
from .. import db
from .types import Finding, EntityType

settings = get_settings()

# ============================================================
# Index du corpus confidentiel.
#
# L'index vit en mémoire (le scan est synchrone et doit rester
# rapide) mais il est PERSISTÉ : sans ça, un redémarrage
# désactiverait silencieusement la protection contre la fuite
# de propriété intellectuelle.
#
# On ne persiste QUE des empreintes non réversibles (shingles
# blake2b, vecteurs) — jamais le texte des documents.
#
# Cloisonné par client : le corpus du client A ne doit jamais
# influencer les scans du client B (ni bloquer ses requêtes, ni
# révéler l'existence de ses documents).
# ============================================================

_lock = threading.Lock()
# client_id -> {hash de shingle -> doc_id}
_SHINGLE_INDEX: dict[str, dict[int, str]] = {}
# client_id -> [chunks + embeddings éventuels]
_DOC_CHUNKS: dict[str, list[dict]] = {}
_EMBED_MODEL = None

DEFAULT_CLIENT = "default"

SHINGLE_N = 5
LEAK_RATIO = 0.15
LEAK_MIN_MATCHED = 4

_WORD = re.compile(r"[a-zàâäéèêëîïôöùûüçœ0-9]+")


def _tokens(text: str) -> list[str]:
    return _WORD.findall(text.lower())


def _shingle_hashes(tokens: list[str], n: int = SHINGLE_N) -> set[int]:
    return {
        int.from_bytes(
            hashlib.blake2b(" ".join(tokens[i:i + n]).encode(), digest_size=8).digest(),
            "big",
        )
        for i in range(max(0, len(tokens) - n + 1))
    }


# ============================================================
# Embeddings (optionnels, dégradation propre si absents)
# ============================================================

def _get_embedder():
    global _EMBED_MODEL
    if _EMBED_MODEL is None:
        try:
            from sentence_transformers import SentenceTransformer
            _EMBED_MODEL = SentenceTransformer("intfloat/multilingual-e5-small")
        except ImportError:
            _EMBED_MODEL = False  # non installé : shingles seuls
    return _EMBED_MODEL or None


def _cosine(a, b) -> float:
    import numpy as np
    a, b = np.asarray(a), np.asarray(b)
    return float(a @ b / ((np.linalg.norm(a) * np.linalg.norm(b)) or 1.0))


# ============================================================
# Ingestion du corpus confidentiel
# ============================================================

def ingest_document(doc_id: str, text: str,
                    client_id: str = DEFAULT_CLIENT) -> dict:
    """Indexe un document confidentiel dans le corpus DU CLIENT :
    shingles + embeddings de chunks."""
    tokens = _tokens(text)
    shingles = _shingle_hashes(tokens)

    with _lock:
        index = _SHINGLE_INDEX.setdefault(client_id, {})
        for h in shingles:
            index[h] = doc_id

    chunk_count = 0
    embedder = _get_embedder()
    if embedder:
        words = text.split()
        chunks = [" ".join(words[i:i + 120]) for i in range(0, len(words), 90)]
        vectors = embedder.encode([f"passage: {c}" for c in chunks])
        with _lock:
            doc_chunks = _DOC_CHUNKS.setdefault(client_id, [])
            for vec in vectors:
                # Le texte du chunk n'est jamais conservé : seul le
                # vecteur sert à la détection.
                doc_chunks.append({"doc_id": doc_id, "vec": vec})
        chunk_count = len(chunks)

    return {"doc_id": doc_id, "shingles": len(shingles), "chunks": chunk_count}


# ============================================================
# Persistance du corpus
# ============================================================

def _to_db(h: int) -> int:
    """uint64 (blake2b) -> int64 signé, domaine d'un BIGINT Postgres."""
    return h - (1 << 64) if h >= (1 << 63) else h


def _from_db(v: int) -> int:
    return v + (1 << 64) if v < 0 else v


def _vec_to_bytes(vec) -> bytes:
    import numpy as np
    return np.asarray(vec, dtype="float32").tobytes()


def _vec_from_bytes(blob: bytes):
    import numpy as np
    return np.frombuffer(blob, dtype="float32")


async def persist_document(doc_id: str,
                           client_id: str = DEFAULT_CLIENT) -> int:
    """Écrit en base les empreintes d'un document déjà ingéré en mémoire.
    Best-effort : une panne de base ne doit pas faire échouer l'ingestion
    (le document reste protégé pour la durée de vie du process)."""
    if not db.is_enabled():
        return 0
    with _lock:
        shingles = [(client_id, _to_db(h), doc_id)
                    for h, d in _SHINGLE_INDEX.get(client_id, {}).items()
                    if d == doc_id]
        chunks = [(client_id, doc_id, _vec_to_bytes(c["vec"]))
                  for c in _DOC_CHUNKS.get(client_id, [])
                  if c["doc_id"] == doc_id]
    try:
        async with db.pool().acquire() as con:
            await con.executemany(
                "INSERT INTO corpus_shingles (client_id, shingle, doc_id) "
                "VALUES ($1, $2, $3) ON CONFLICT (client_id, shingle) "
                "DO UPDATE SET doc_id = EXCLUDED.doc_id", shingles)
            # Ré-ingestion du même document : on remplace ses vecteurs.
            await con.execute(
                "DELETE FROM corpus_chunks WHERE client_id = $1 AND doc_id = $2",
                client_id, doc_id)
            if chunks:
                await con.executemany(
                    "INSERT INTO corpus_chunks (client_id, doc_id, vec) "
                    "VALUES ($1, $2, $3)", chunks)
        return len(shingles)
    except Exception as e:
        from .. import logs
        logs.get_logger("corpus").warning(
            "persistance corpus echouee",
            extra={"event": "db_error", "op": "persist_document",
                   "doc_id": doc_id, "error": f"{type(e).__name__}: {e}"})
        return 0


async def load_corpus_from_db() -> int:
    """Recharge le corpus au démarrage. Sans ça, la protection contre la
    fuite de propriété intellectuelle serait inactive après un
    redémarrage, silencieusement."""
    if not db.is_enabled():
        return 0
    try:
        async with db.pool().acquire() as con:
            shingles = await con.fetch(
                "SELECT client_id, shingle, doc_id FROM corpus_shingles")
            chunks = await con.fetch(
                "SELECT client_id, doc_id, vec FROM corpus_chunks")
    except Exception as e:
        from .. import logs
        logs.get_logger("corpus").warning(
            "rechargement corpus impossible",
            extra={"event": "db_error", "op": "load_corpus",
                   "error": f"{type(e).__name__}: {e}"})
        return 0

    with _lock:
        _SHINGLE_INDEX.clear()
        _DOC_CHUNKS.clear()
        for r in shingles:
            _SHINGLE_INDEX.setdefault(r["client_id"], {})[
                _from_db(r["shingle"])] = r["doc_id"]
        for r in chunks:
            _DOC_CHUNKS.setdefault(r["client_id"], []).append(
                {"doc_id": r["doc_id"], "vec": _vec_from_bytes(r["vec"])})

    from .. import logs
    logs.get_logger("corpus").info(
        "corpus recharge", extra={
            "event": "corpus_loaded", "clients": len(_SHINGLE_INDEX),
            "shingles": len(shingles), "chunks": len(chunks)})
    return len(shingles)


async def forget_document(doc_id: str,
                          client_id: str = DEFAULT_CLIENT) -> int:
    """Retire un document du corpus (mémoire + base). Son contenu n'est
    plus protégé : à utiliser quand un document devient public ou a été
    indexé par erreur. Renvoie le nombre d'empreintes supprimées."""
    with _lock:
        index = _SHINGLE_INDEX.get(client_id, {})
        removed = [h for h, d in index.items() if d == doc_id]
        for h in removed:
            del index[h]
        chunks = _DOC_CHUNKS.get(client_id)
        if chunks:
            _DOC_CHUNKS[client_id] = [c for c in chunks
                                      if c["doc_id"] != doc_id]

    if db.is_enabled():
        try:
            async with db.pool().acquire() as con:
                await con.execute(
                    "DELETE FROM corpus_shingles "
                    "WHERE client_id = $1 AND doc_id = $2", client_id, doc_id)
                await con.execute(
                    "DELETE FROM corpus_chunks "
                    "WHERE client_id = $1 AND doc_id = $2", client_id, doc_id)
        except Exception as e:
            from .. import logs
            logs.get_logger("corpus").warning(
                "suppression corpus echouee",
                extra={"event": "db_error", "op": "forget_document",
                       "doc_id": doc_id, "error": f"{type(e).__name__}: {e}"})
    return len(removed)


def corpus_stats(client_id: str = DEFAULT_CLIENT) -> dict:
    """Statistiques du corpus DU CLIENT uniquement — ne jamais révéler
    l'existence de documents d'autres tenants."""
    return {
        "client_id": client_id,
        "shingles_indexed": len(_SHINGLE_INDEX.get(client_id, {})),
        "embedded_chunks": len(_DOC_CHUNKS.get(client_id, [])),
        "embeddings_active": _get_embedder() is not None,
    }


# ============================================================
# Détection
# ============================================================

def scan_sync(text: str, client_id: str = DEFAULT_CLIENT) -> list[Finding]:
    """Detecte une fuite de contenu confidentiel contre le corpus DU CLIENT
    uniquement (isolation multi-tenant)."""
    findings: list[Finding] = []
    shingle_index = _SHINGLE_INDEX.get(client_id, {})
    doc_chunks = _DOC_CHUNKS.get(client_id, [])
    if not shingle_index and not doc_chunks:
        return findings

    tokens = _tokens(text)

    # --- Niveau 1 : containment de shingles (copie, quasi-copie) ---
    prompt_shingles = _shingle_hashes(tokens)
    if prompt_shingles:
        matched = prompt_shingles & set(shingle_index.keys())
        ratio = len(matched) / len(prompt_shingles)
        if ratio >= LEAK_RATIO and len(matched) >= LEAK_MIN_MATCHED:
            source_docs = {shingle_index[h] for h in matched}
            findings.append(Finding(
                entity_type=EntityType.IP_LEAK,
                start=0, end=len(text), value=text[:80],
                confidence=min(0.99, 0.6 + ratio * 0.4),
                layer="L3",
                meta={
                    "method": "shingle_containment",
                    "ratio": round(ratio, 3),
                    "matched_shingles": len(matched),
                    "source_docs": sorted(source_docs),
                },
            ))
            return findings  # copie avérée : inutile d'aller plus loin

    # --- Niveau 2 : similarité sémantique (reformulation) ---
    embedder = _get_embedder()
    if embedder and doc_chunks and len(tokens) >= 8:
        qvec = embedder.encode([f"query: {text}"])[0]
        best_sim, best_doc = 0.0, None
        for chunk in doc_chunks:
            sim = _cosine(qvec, chunk["vec"])
            if sim > best_sim:
                best_sim, best_doc = sim, chunk["doc_id"]
        if best_sim >= settings.l3_similarity_threshold:
            findings.append(Finding(
                entity_type=EntityType.IP_LEAK,
                start=0, end=len(text), value=text[:80],
                confidence=best_sim,
                layer="L3",
                meta={
                    "method": "semantic_similarity",
                    "similarity": round(best_sim, 3),
                    "source_doc": best_doc,
                },
            ))

    return findings