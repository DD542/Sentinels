from __future__ import annotations
import asyncio
import time
from collections import deque

from . import metrics
from . import logs

_log = logs.get_logger("events")

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
}


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
    if kind == "scan":
        _STATS["prompts_scanned"] += 1
    elif kind == "provider":
        register_provider(event.get("provider", "?"))
    elif kind == "decision":
        action = event.get("action")
        etype = event.get("entity_type", "?")
        if action == "TOKENIZE":
            _STATS["entities_tokenized"] += 1
            _register_type(etype)
        elif action == "BLOCK":
            _STATS["secrets_blocked"] += 1
            _register_type(etype)
        elif action == "BLOCK_REQUEST":
            _STATS["requests_blocked"] += 1
            _STATS["ip_leaks_blocked"] += 1

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