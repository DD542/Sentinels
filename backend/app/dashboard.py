from __future__ import annotations
import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from . import events
from .audit import chain

router = APIRouter()


@router.get("/dashboard/stats")
async def stats() -> dict:
    """Compteurs cumulés + événements récents pour le chargement initial."""
    snap = events.snapshot()
    snap["audit_integrity"] = chain.verify_integrity()
    return snap


@router.post("/dashboard/reset")
async def reset() -> dict:
    events.reset()
    return {"status": "reset"}


@router.websocket("/dashboard/ws")
async def ws(websocket: WebSocket) -> None:
    """Flux temps réel : chaque décision arrive ici en direct."""
    await websocket.accept()
    queue = events.subscribe()
    try:
        # État initial à la connexion
        await websocket.send_json({"kind": "snapshot", **events.snapshot()})
        while True:
            event = await queue.get()
            await websocket.send_json(event)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        events.unsubscribe(queue)