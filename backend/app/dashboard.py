from __future__ import annotations
import secrets
from fastapi import (APIRouter, Depends, Header, HTTPException, Request,
                     WebSocket, WebSocketDisconnect)

from . import events
from .audit import chain
from .config import get_settings

settings = get_settings()
router = APIRouter()

# Sous-protocole WebSocket : les navigateurs ne peuvent pas envoyer de header
# sur un WS, et un token en query string finirait dans les logs serveur.
# Le client envoie donc ["sentinel.v1", "<token>"] via Sec-WebSocket-Protocol.
WS_SUBPROTOCOL = "sentinel.v1"


def _token_ok(candidate: str | None) -> bool:
    """Vrai si le dashboard est ouvert (pas de token configure) ou si le
    token fourni correspond (comparaison en temps constant)."""
    if not settings.dashboard_token:
        return True
    return candidate is not None and secrets.compare_digest(
        candidate, settings.dashboard_token)


async def require_dashboard_token(
        request: Request,
        x_dashboard_token: str | None = Header(default=None)) -> None:
    """Deux voies d'accès : la session SSO (nominative, révocable avec le
    compte) et le token partagé (accès de secours, automatisation)."""
    from . import sso
    if sso.read_session(request.cookies.get(sso.SESSION_COOKIE)):
        return
    if not _token_ok(x_dashboard_token):
        raise HTTPException(
            status_code=401,
            detail=("Authentification requise : connectez-vous "
                    "(/auth/login) ou fournissez le header X-Dashboard-Token")
            if settings.sso_enabled else
            "Token dashboard invalide ou manquant (header X-Dashboard-Token)")


@router.get("/dashboard/stats", dependencies=[Depends(require_dashboard_token)])
async def stats() -> dict:
    """Compteurs cumulés + événements récents pour le chargement initial."""
    snap = events.snapshot()
    snap["audit_integrity"] = chain.integrity_status()["verified"]
    return snap


@router.post("/dashboard/reset", dependencies=[Depends(require_dashboard_token)])
async def reset() -> dict:
    events.reset()
    return {"status": "reset"}


@router.websocket("/dashboard/ws")
async def ws(websocket: WebSocket) -> None:
    """Flux temps réel : chaque décision arrive ici en direct.
    Si DASHBOARD_TOKEN est défini, le client doit le présenter en second
    sous-protocole ; sinon la connexion est refusée avant tout envoi."""
    offered = websocket.scope.get("subprotocols") or []
    candidate = offered[1] if len(offered) > 1 else None
    # Le navigateur envoie les cookies sur la poignée de main WebSocket :
    # une session SSO ouverte suffit, sans exposer de secret dans l'URL.
    from . import sso
    session = sso.read_session(websocket.cookies.get(sso.SESSION_COOKIE))

    # Si le client a proposé un sous-protocole, il faut le confirmer,
    # sinon le navigateur ferme la connexion.
    subprotocol = WS_SUBPROTOCOL if WS_SUBPROTOCOL in offered else None
    await websocket.accept(subprotocol=subprotocol)

    # Refus APRES accept : un refus de handshake arriverait au navigateur
    # en code 1006 generique ; ici le client recoit un 1008 explicite
    # (policy violation) et peut afficher l'ecran de saisie du token.
    if not session and not _token_ok(candidate):
        await websocket.close(code=1008)
        return
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
