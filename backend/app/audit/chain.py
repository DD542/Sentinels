from __future__ import annotations
import hashlib
import hmac
import json
import os
import time
from ..config import get_settings

settings = get_settings()
_HMAC_KEY = bytes.fromhex(settings.audit_hmac_key)

# Journal en mémoire pour la démo (en prod : table Postgres append-only)
_CHAIN: list[dict] = []
_GENESIS = "0" * 64


def _entity_key(entity_id: str) -> bytes:
    """Clé de chiffrement dérivée par entité (crypto-shredding)."""
    return hmac.new(_HMAC_KEY, entity_id.encode(), hashlib.sha256).digest()


def _seal(payload: dict, prev_hash: str) -> str:
    material = json.dumps(payload, sort_keys=True) + prev_hash
    return hmac.new(_HMAC_KEY, material.encode(), hashlib.sha256).hexdigest()


def append(action: str, entity_type: str, entity_id: str, detail: dict) -> dict:
    prev_hash = _CHAIN[-1]["hash"] if _CHAIN else _GENESIS
    # Le détail sensible n'est jamais en clair : chiffré par clé d'entité.
    key = _entity_key(entity_id)
    blob = json.dumps(detail).encode()
    ciphertext = bytes(b ^ key[i % len(key)] for i, b in enumerate(blob)).hex()

    entry = {
        "ts": time.time(),
        "action": action,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "cipher": ciphertext,
        "prev_hash": prev_hash,
    }
    entry["hash"] = _seal(entry, prev_hash)
    _CHAIN.append(entry)
    return entry


def verify_integrity() -> bool:
    """Rejoue la chaîne : toute altération casse un maillon."""
    prev = _GENESIS
    for entry in _CHAIN:
        expected = _seal({k: v for k, v in entry.items() if k != "hash"}, prev)
        if entry["hash"] != expected or entry["prev_hash"] != prev:
            return False
        prev = entry["hash"]
    return True