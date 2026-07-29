"""Chiffrement authentifié de la chaîne d'audit + crypto-shredding.

Remplace l'ancien XOR (réversible trivialement) par du Fernet
(AES-128-CBC + HMAC-SHA256, horodaté, authentifié).

Modèle de clés — crypto-shredding conforme RGPD art. 17 :
  * chaque `entity_id` possède une clé de données ALÉATOIRE (DEK),
    partagée par toutes ses entrées d'audit ;
  * cette DEK est stockée ENVELOPPÉE (chiffrée) par une clé maître
    (KEK) dérivée de `audit_hmac_key` ;
  * « oublier » une entité = détruire sa DEK (`forget`). Le détail
    devient définitivement indéchiffrable, alors que la chaîne de
    hachage (preuve d'inviolabilité) reste intacte : on prouve
    qu'un événement a eu lieu sans jamais pouvoir relire la donnée.

Repli mémoire si pas de base : le keyring vit en RAM.
"""
from __future__ import annotations
import base64
import hashlib
import json

from cryptography.fernet import Fernet, InvalidToken

from ..config import get_settings

settings = get_settings()

# Keyring mémoire : entity_id -> DEK enveloppée (str Fernet). Source de
# vérité si pas de DB ; sinon miroir du cache rechargé au démarrage.
_KEYRING: dict[str, str] = {}


def _kek() -> Fernet:
    """Clé d'enveloppe (KEK) dérivée de la clé HMAC d'audit.

    Domaine séparé (`audit-kek`) pour ne jamais réutiliser le même
    matériel que le scellage de la chaîne ni que le vault."""
    raw = hashlib.sha256(
        bytes.fromhex(settings.audit_hmac_key) + b"audit-kek"
    ).digest()
    return Fernet(base64.urlsafe_b64encode(raw))


def wrap_key(dek: bytes) -> str:
    return _kek().encrypt(dek).decode()


def unwrap_key(wrapped: str) -> bytes | None:
    try:
        return _kek().decrypt(wrapped.encode())
    except (InvalidToken, ValueError):
        return None


def new_dek() -> bytes:
    """Nouvelle clé de données aléatoire (44 octets urlsafe-b64 Fernet)."""
    return Fernet.generate_key()


def encrypt_detail(detail: dict, dek: bytes) -> str:
    return Fernet(dek).encrypt(json.dumps(detail).encode()).decode()


def decrypt_detail(cipher: str, dek: bytes) -> dict | None:
    try:
        return json.loads(Fernet(dek).decrypt(cipher.encode()).decode())
    except (InvalidToken, ValueError):
        return None
