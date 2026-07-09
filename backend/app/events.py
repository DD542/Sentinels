from __future__ import annotations
import asyncio
import time
from collections import deque

# Historique récent en mémoire (démo ; prod : Postgres + Redis pub/sub)
_HISTORY: deque[dict] = deque(maxlen=200)
_SUBSCRIBERS: set[asyncio.Queue] = set()

# Compteurs cumulés pour le dashboard
_STATS = {
    "prompts_scanned": 0,
    "requests_blocked": 0,
    "entities_tokenized": 0,
    "secrets_blocked": 0,
    "ip_leaks_blocked": 0,
    "by_type": {},        # {"IBAN": 12, "PERSON": 8, ...}
}


def _register_type(entity_type: str) -> None:
    _STATS["by_type"][entity_type] = _STATS["by_type"].get(entity_type, 0) + 1


async def publish(event: dict) -> None:
    """Diffuse un événement à tous les abonnés WebSocket + historise."""
    event = {"ts": time.time(), **event}
    _HISTORY.appendleft(event)

    # Mise à jour des compteurs selon le type d'événement
    kind = event.get("kind")
    if kind == "scan":
        _STATS["prompts_scanned"] += 1
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
        pass  # pas de boucle : on ignore silencieusement


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