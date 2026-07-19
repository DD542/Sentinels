from __future__ import annotations
import asyncio
import time
from collections import deque

from . import metrics
from . import logs
from . import db

_log = logs.get_logger("events")

# Colonnes autorisees pour l'upsert usage (jamais d'interpolation libre)
_USAGE_FIELDS = {"prompts", "tokenized", "blocked"}

# Historique récent en mémoire (démo ; prod : Postgres + Redis pub/sub)
_HISTORY: deque[dict] = deque(maxlen=200)
_SUBSCRIBERS: set[asyncio.Queue] = set()

_STATS = {
    "prompts_scanned": 0,
    "requests_blocked": 0,
    "entities_tokenized": 0,
    "secrets_blocked": 0,
    "ip_leaks_blocked": 0,
    "by_type": {},
    "by_provider": {},   # {"groq": 12, "anthropic": 3, ...}
    # Metering par client — base de facturation a l'usage.
    # {client_id: {"prompts": n, "tokenized": n, "blocked": n}}
    "by_client": {},
}


def _client_bucket(client_id: str) -> dict:
    return _STATS["by_client"].setdefault(
        client_id, {"prompts": 0, "tokenized": 0, "blocked": 0})


async def _persist_usage(client_id: str, field: str) -> None:
    """Incremente le compteur (client, jour) en DB. Best-effort : une
    erreur DB ne doit jamais bloquer le pipeline de scan."""
    if not db.is_enabled() or field not in _USAGE_FIELDS:
        return
    try:
        async with db.pool().acquire() as con:
            await con.execute(
                f"INSERT INTO usage_counters (client_id, day, {field}) "
                f"VALUES ($1, CURRENT_DATE, 1) "
                f"ON CONFLICT (client_id, day) DO UPDATE "
                f"SET {field} = usage_counters.{field} + 1",
                client_id)
    except Exception as e:
        _log.warning("ecriture usage DB echouee", extra={
            "event": "db_error", "op": "upsert_usage",
            "error": f"{type(e).__name__}: {e}"})


async def _persist_provider(provider: str) -> None:
    if not db.is_enabled():
        return
    try:
        async with db.pool().acquire() as con:
            await con.execute(
                "INSERT INTO provider_counters (provider, requests) "
                "VALUES ($1, 1) ON CONFLICT (provider) DO UPDATE "
                "SET requests = provider_counters.requests + 1",
                provider)
    except Exception as e:
        _log.warning("ecriture provider DB echouee", extra={
            "event": "db_error", "op": "upsert_provider",
            "error": f"{type(e).__name__}: {e}"})


def _apply_chain_aggregate(action: str, entity_type: str, count: int) -> None:
    """Reapplique un agregat de la chaine d'audit aux compteurs memoire.
    Meme logique que publish() ; les actions hors decisions (CORPUS_INGEST,
    KEY_REVOKED, EVASION_ATTEMPT...) sont ignorees."""
    if action == "TOKENIZE":
        _STATS["entities_tokenized"] += count
        _STATS["by_type"][entity_type] = \
            _STATS["by_type"].get(entity_type, 0) + count
    elif action == "BLOCK":
        _STATS["secrets_blocked"] += count
        _STATS["by_type"][entity_type] = \
            _STATS["by_type"].get(entity_type, 0) + count
    elif action == "BLOCK_REQUEST":
        _STATS["requests_blocked"] += count
        _STATS["ip_leaks_blocked"] += count


async def load_stats_from_db() -> None:
    """Reconstruit les compteurs au demarrage depuis la DB : le dashboard
    et le metering survivent aux redemarrages. No-op sans persistance."""
    if not db.is_enabled():
        return
    try:
        async with db.pool().acquire() as con:
            usage = await con.fetch(
                "SELECT client_id, SUM(prompts) AS p, SUM(tokenized) AS t, "
                "SUM(blocked) AS b FROM usage_counters GROUP BY client_id")
            chain_agg = await con.fetch(
                "SELECT action, entity_type, COUNT(*) AS n "
                "FROM audit_chain GROUP BY action, entity_type")
            providers = await con.fetch(
                "SELECT provider, requests FROM provider_counters")

        for r in usage:
            _STATS["by_client"][r["client_id"]] = {
                "prompts": int(r["p"]), "tokenized": int(r["t"]),
                "blocked": int(r["b"])}
            _STATS["prompts_scanned"] += int(r["p"])
        for r in chain_agg:
            _apply_chain_aggregate(r["action"], r["entity_type"], int(r["n"]))
        for r in providers:
            _STATS["by_provider"][r["provider"]] = int(r["requests"])
        _log.info("compteurs recharges depuis la DB", extra={
            "event": "stats_loaded", "clients": len(usage),
            "prompts": _STATS["prompts_scanned"]})
    except Exception as e:
        _log.warning("rechargement compteurs impossible", extra={
            "event": "db_error", "op": "load_stats",
            "error": f"{type(e).__name__}: {e}"})


def _log_event(event: dict) -> None:
    """Une ligne de log structuree par evenement metier. Jamais la valeur
    detectee : uniquement le type, l'action et le hash d'audit."""
    kind = event.get("kind")
    if kind == "decision":
        _log.info("decision", extra={
            "event": "decision",
            "action": event.get("action"),
            "entity_type": event.get("entity_type"),
            "layer": event.get("layer"),
            "confidence": event.get("confidence"),
            "audit_hash": event.get("audit_hash"),
        })
    elif kind == "provider":
        _log.info("appel fournisseur", extra={
            "event": "provider_call", "provider": event.get("provider")})
    elif kind == "scan":
        _log.info("prompt analyse", extra={
            "event": "scan", "length": event.get("length")})


def _register_type(entity_type: str) -> None:
    _STATS["by_type"][entity_type] = _STATS["by_type"].get(entity_type, 0) + 1


def register_provider(provider: str) -> None:
    _STATS["by_provider"][provider] = _STATS["by_provider"].get(provider, 0) + 1


async def publish(event: dict) -> None:
    """Diffuse un événement à tous les abonnés WebSocket + historise."""
    event = {"ts": time.time(), **event}
    _HISTORY.appendleft(event)
    metrics.record_event(event)
    _log_event(event)

    kind = event.get("kind")
    client = event.get("client")
    if kind == "scan":
        _STATS["prompts_scanned"] += 1
        if client:
            _client_bucket(client)["prompts"] += 1
            await _persist_usage(client, "prompts")
    elif kind == "provider":
        register_provider(event.get("provider", "?"))
        await _persist_provider(event.get("provider", "?"))
    elif kind == "decision":
        action = event.get("action")
        etype = event.get("entity_type", "?")
        if action == "TOKENIZE":
            _STATS["entities_tokenized"] += 1
            _register_type(etype)
            if client:
                _client_bucket(client)["tokenized"] += 1
                await _persist_usage(client, "tokenized")
        elif action == "BLOCK":
            _STATS["secrets_blocked"] += 1
            _register_type(etype)
            if client:
                _client_bucket(client)["blocked"] += 1
                await _persist_usage(client, "blocked")
        elif action == "BLOCK_REQUEST":
            _STATS["requests_blocked"] += 1
            _STATS["ip_leaks_blocked"] += 1
            if client:
                _client_bucket(client)["blocked"] += 1
                await _persist_usage(client, "blocked")

    dead = []
    for q in _SUBSCRIBERS:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            dead.append(q)
    for q in dead:
        _SUBSCRIBERS.discard(q)


def publish_sync(event: dict) -> None:
    """Version appelable depuis un contexte synchrone (best-effort)."""
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(publish(event))
    except RuntimeError:
        pass


def subscribe() -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue(maxsize=100)
    _SUBSCRIBERS.add(q)
    return q


def unsubscribe(q: asyncio.Queue) -> None:
    _SUBSCRIBERS.discard(q)


def snapshot() -> dict:
    return {"stats": dict(_STATS), "recent": list(_HISTORY)[:50]}


def reset() -> None:
    _HISTORY.clear()
    for k in ("prompts_scanned", "requests_blocked", "entities_tokenized",
              "secrets_blocked", "ip_leaks_blocked"):
        _STATS[k] = 0
    _STATS["by_type"] = {}
    _STATS["by_provider"] = {}
    _STATS["by_client"] = {}