"""
Rate-limiting par client : fenetre glissante de 60 secondes, en memoire.
Chaque client (client_id resolu depuis sa cle SENTINEL) dispose d'un quota
de requetes par minute, configurable via RATE_LIMIT_PER_MINUTE (0 = off).
"""
from __future__ import annotations
import time
from collections import deque
from fastapi import HTTPException

from .config import get_settings

settings = get_settings()

# client_id -> horodatages (monotonic) des requetes de la derniere minute
_WINDOWS: dict[str, deque] = {}

_WINDOW_SECONDS = 60.0


def check(client_id: str) -> None:
    """Enregistre la requete et leve 429 si le quota par minute est depasse.
    Le header Retry-After indique au client quand reessayer."""
    limit = settings.rate_limit_per_minute
    if limit <= 0:
        return

    now = time.monotonic()
    window = _WINDOWS.setdefault(client_id, deque())
    while window and now - window[0] >= _WINDOW_SECONDS:
        window.popleft()

    if len(window) >= limit:
        retry_after = max(1, int(_WINDOW_SECONDS - (now - window[0])) + 1)
        raise HTTPException(
            status_code=429,
            detail=f"Quota depasse : {limit} requetes/minute pour ce client",
            headers={"Retry-After": str(retry_after)},
        )

    window.append(now)
