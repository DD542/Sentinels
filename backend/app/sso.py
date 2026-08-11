"""
SSO d'entreprise pour le dashboard — OpenID Connect (code + PKCE).

Pourquoi OIDC plutôt que SAML : les deux répondent au même besoin, mais
SAML impose en Python la chaîne `python3-saml`/`xmlsec` (bibliothèque C
lourde à installer) et une famille de vulnérabilités bien connue liée à
la signature XML (*signature wrapping*). OIDC vérifie un JWT signé avec
des clés publiées en JWKS : plus simple, et supporté par tous les
fournisseurs d'identité d'entreprise (Entra ID, Okta, Keycloak, Google
Workspace). Les organisations qui imposent SAML peuvent placer devant
SENTINEL un proxy d'identité (oauth2-proxy, Pomerium) — voir la doc.

Ce que le SSO change concrètement : le token de dashboard partagé ne
permet ni de savoir *qui* a consulté la console, ni de retirer l'accès
d'une personne qui quitte l'entreprise. Avec le SSO, chaque connexion
est nominative et scellée dans le journal d'audit, et l'accès disparaît
avec le compte.

Le token partagé reste accepté en **accès de secours** (automatisation,
fournisseur d'identité indisponible).
"""
from __future__ import annotations
import base64
import hashlib
import json
import secrets
import time
from urllib.parse import urlencode

import httpx
import jwt
from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from .config import get_settings
from .audit import chain
from . import logs

settings = get_settings()
router = APIRouter()
_log = logs.get_logger("sso")

SESSION_COOKIE = "sentinel_session"
_STATE_COOKIE = "sentinel_oidc_state"
_STATE_TTL_SECONDS = 600          # 10 min pour terminer une connexion

# Métadonnées du fournisseur, découvertes une fois puis mises en cache.
_discovery: dict | None = None
_jwks_client: jwt.PyJWKClient | None = None


# ============================================================
# Session : cookie chiffré et authentifié (Fernet)
# ============================================================

def _session_key() -> Fernet:
    """Clé à domaine séparé : ne réutilise ni le scellement de la chaîne,
    ni l'enveloppe des clés d'audit, ni l'index des personnes."""
    raw = hashlib.sha256(
        bytes.fromhex(settings.audit_hmac_key) + b"dashboard-session").digest()
    return Fernet(base64.urlsafe_b64encode(raw))


def issue_session(identity: dict) -> str:
    payload = json.dumps({**identity, "iat": int(time.time())})
    return _session_key().encrypt(payload.encode()).decode()


def read_session(token: str | None) -> dict | None:
    """Identité portée par le cookie, ou None si absent, altéré ou expiré.
    Fernet horodate le jeton : le TTL est vérifié à la lecture."""
    if not token:
        return None
    try:
        raw = _session_key().decrypt(
            token.encode(), ttl=settings.session_ttl_hours * 3600)
        return json.loads(raw)
    except (InvalidToken, ValueError):
        return None


# ============================================================
# Découverte OIDC
# ============================================================

async def _discover() -> dict:
    global _discovery, _jwks_client
    if _discovery is not None:
        return _discovery
    url = settings.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        _discovery = resp.json()
    _jwks_client = jwt.PyJWKClient(_discovery["jwks_uri"])
    _log.info("fournisseur d'identite decouvert", extra={
        "event": "oidc_discovery", "issuer": _discovery.get("issuer")})
    return _discovery


def _reset_discovery_cache() -> None:
    """Utilisé par les tests ; en production la découverte est stable."""
    global _discovery, _jwks_client
    _discovery, _jwks_client = None, None


# ============================================================
# Contrôle d'accès : qui a le droit d'entrer
# ============================================================

def _csv(value: str) -> list[str]:
    return [v.strip().lower() for v in value.split(",") if v.strip()]


def authorize(claims: dict) -> str | None:
    """Renvoie None si l'accès est accordé, sinon la raison du refus.

    Sans restriction configurée, on refuse : un fournisseur d'identité
    public (Google Workspace, Entra multi-tenant) laisserait sinon entrer
    n'importe quel compte du monde."""
    domains = _csv(settings.oidc_allowed_domains)
    groups = _csv(settings.oidc_allowed_groups)
    if not domains and not groups:
        return ("aucune restriction configuree "
                "(oidc_allowed_domains ou oidc_allowed_groups)")

    if domains:
        email = str(claims.get("email") or "").lower()
        if not claims.get("email_verified", True):
            return "adresse de messagerie non verifiee par le fournisseur"
        domain = email.rpartition("@")[2]
        if domain and domain in domains:
            return None

    if groups:
        revendiques = claims.get("groups") or claims.get("roles") or []
        if isinstance(revendiques, str):
            revendiques = [revendiques]
        if {str(g).lower() for g in revendiques} & set(groups):
            return None

    return "compte hors du perimetre autorise"


# ============================================================
# Flux d'autorisation
# ============================================================

def _pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


def _safe_next(value: str | None) -> str:
    """Empêche une redirection ouverte : seules les cibles internes sont
    acceptées (`//evil.com` est une URL absolue, pas un chemin)."""
    if not value or not value.startswith("/") or value.startswith("//"):
        return "/"
    return value


@router.get("/auth/config")
async def auth_config() -> dict:
    """Consommé par le dashboard pour savoir quoi afficher : bouton de
    connexion SSO ou saisie du token."""
    return {"sso_enabled": settings.sso_enabled,
            "login_url": "/auth/login" if settings.sso_enabled else None,
            "token_fallback": bool(settings.dashboard_token)}


@router.get("/auth/login")
async def login(request: Request, next: str | None = None):
    if not settings.sso_enabled:
        raise HTTPException(status_code=404, detail="SSO non configure")
    meta = await _discover()

    verifier, challenge = _pkce_pair()
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    params = {
        "client_id": settings.oidc_client_id,
        "response_type": "code",
        "redirect_uri": settings.oidc_redirect_uri,
        "scope": settings.oidc_scopes,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    response = RedirectResponse(
        meta["authorization_endpoint"] + "?" + urlencode(params), status_code=302)
    # `state`, `nonce` et le vérifiant PKCE voyagent dans un cookie chiffré :
    # pas de session serveur, et le flux résiste à un redémarrage ou à
    # plusieurs répliques.
    response.set_cookie(
        _STATE_COOKIE,
        _session_key().encrypt(json.dumps({
            "state": state, "nonce": nonce, "verifier": verifier,
            "next": _safe_next(next)}).encode()).decode(),
        max_age=_STATE_TTL_SECONDS, httponly=True,
        secure=settings.session_cookie_secure, samesite="lax")
    return response


@router.get("/auth/callback")
async def callback(request: Request, code: str | None = None,
                   state: str | None = None, error: str | None = None):
    if not settings.sso_enabled:
        raise HTTPException(status_code=404, detail="SSO non configure")
    if error:
        raise HTTPException(status_code=401,
                            detail=f"Refus du fournisseur d'identite : {error}")
    if not code or not state:
        raise HTTPException(status_code=400, detail="Reponse OIDC incomplete")

    # --- Vérifie que la requête vient bien de notre propre redirection ---
    brut = request.cookies.get(_STATE_COOKIE)
    try:
        contexte = json.loads(_session_key().decrypt(
            (brut or "").encode(), ttl=_STATE_TTL_SECONDS))
    except (InvalidToken, ValueError, AttributeError):
        raise HTTPException(status_code=400,
                            detail="Contexte de connexion absent ou expire")
    if not secrets.compare_digest(str(contexte.get("state", "")), state):
        raise HTTPException(status_code=400, detail="Parametre state invalide")

    meta = await _discover()

    # --- Échange du code contre les jetons ---
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.oidc_redirect_uri,
        "client_id": settings.oidc_client_id,
        "code_verifier": contexte["verifier"],
    }
    if settings.oidc_client_secret:
        data["client_secret"] = settings.oidc_client_secret
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(meta["token_endpoint"], data=data)
    if resp.status_code != 200:
        _log.warning("echange du code refuse", extra={
            "event": "oidc_token_error", "status": resp.status_code})
        raise HTTPException(status_code=401,
                            detail="Echange du code refuse par le fournisseur")
    id_token = resp.json().get("id_token")
    if not id_token:
        raise HTTPException(status_code=401, detail="Aucun id_token renvoye")

    claims = verify_id_token(id_token, contexte["nonce"])

    refus = authorize(claims)
    if refus:
        _log.warning("connexion refusee", extra={
            "event": "sso_denied", "reason": refus})
        await chain.append_async(
            "AUTH_DENIED", "SSO", f"sso:{claims.get('sub', '?')}",
            {"email": claims.get("email"), "reason": refus},
            subject=claims.get("email"))
        raise HTTPException(status_code=403, detail=f"Acces refuse : {refus}")

    identity = {
        "sub": claims.get("sub"),
        "email": claims.get("email"),
        "name": claims.get("name") or claims.get("preferred_username"),
    }
    # Connexion nominative scellée : c'est ce que le token partagé ne
    # permettait pas. L'identité est indexée en aveugle et chiffrée.
    entry = await chain.append_async(
        "AUTH_LOGIN", "SSO", f"sso:{identity['sub']}",
        {"email": identity["email"], "name": identity["name"]},
        subject=identity["email"])
    _log.info("connexion SSO", extra={
        "event": "sso_login", "audit_hash": entry["hash"][:12]})

    response = RedirectResponse(_safe_next(contexte.get("next")), status_code=302)
    response.set_cookie(
        SESSION_COOKIE, issue_session(identity),
        max_age=settings.session_ttl_hours * 3600, httponly=True,
        secure=settings.session_cookie_secure, samesite="lax")
    response.delete_cookie(_STATE_COOKIE)
    return response


def verify_id_token(id_token: str, nonce: str | None = None) -> dict:
    """Vérifie signature (JWKS), émetteur, audience, expiration et nonce.
    Toute défaillance est un 401 : on ne laisse jamais passer un jeton
    dont on n'a pas pu établir l'origine."""
    if _jwks_client is None:
        raise HTTPException(status_code=503,
                            detail="Fournisseur d'identite non decouvert")
    try:
        signing_key = _jwks_client.get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token, signing_key.key,
            algorithms=["RS256", "RS384", "RS512", "ES256"],
            audience=settings.oidc_client_id,
            issuer=(_discovery or {}).get("issuer") or settings.oidc_issuer,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
    except Exception as e:
        _log.warning("id_token rejete", extra={
            "event": "oidc_token_invalid", "error": type(e).__name__})
        raise HTTPException(status_code=401,
                            detail=f"Jeton d'identite invalide : {type(e).__name__}")

    if nonce is not None and not secrets.compare_digest(
            str(claims.get("nonce", "")), nonce):
        raise HTTPException(status_code=401, detail="Nonce invalide")
    return claims


@router.post("/auth/logout")
async def logout() -> JSONResponse:
    response = JSONResponse({"status": "deconnecte"})
    response.delete_cookie(SESSION_COOKIE)
    return response
