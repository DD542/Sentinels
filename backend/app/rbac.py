"""
Rôles et permissions de la console.

Jusqu'ici, quiconque franchissait la porte voyait tout : le flux des
décisions, la facturation, les clés, l'effacement RGPD. Or ces écrans
n'intéressent pas les mêmes personnes et n'engagent pas les mêmes
responsabilités.

Trois rôles, calqués sur les fonctions réelles :

* **administrateur** (exploitant, RSSI) — tout, y compris les clés, la
  consommation facturable et la maintenance ;
* **auditeur** (DPO, contrôle interne, commissaire aux comptes) — les
  rapports de conformité, les droits des personnes et la vérification du
  journal. **Pas** les clés, **pas** la facturation : un auditeur n'a
  aucune raison de pouvoir créer un accès ;
* **observateur** (analyste sécurité) — le flux temps réel, rien d'autre.

Le rôle vient du fournisseur d'identité quand le SSO est actif (par
correspondance de groupes), sinon du jeton présenté. Aucun rôle par
défaut : ce qui n'est pas attribué est refusé.
"""
from __future__ import annotations
import secrets

from fastapi import Header, HTTPException, Request

from .config import get_settings
from . import logs

settings = get_settings()
_log = logs.get_logger("rbac")

ADMIN = "administrateur"
AUDITOR = "auditeur"
VIEWER = "observateur"

# Permissions : verbe métier, pas nom d'endpoint. Ajouter une route ne
# doit pas obliger à toucher la matrice.
DASHBOARD_READ = "dashboard:read"
COMPLIANCE_READ = "compliance:read"
GDPR_MANAGE = "gdpr:manage"
AUDIT_VERIFY = "audit:verify"
KEYS_MANAGE = "keys:manage"
USAGE_READ = "usage:read"
MAINTENANCE_RUN = "maintenance:run"

_MATRICE: dict[str, set[str]] = {
    ADMIN: {DASHBOARD_READ, COMPLIANCE_READ, GDPR_MANAGE, AUDIT_VERIFY,
            KEYS_MANAGE, USAGE_READ, MAINTENANCE_RUN},
    AUDITOR: {DASHBOARD_READ, COMPLIANCE_READ, GDPR_MANAGE, AUDIT_VERIFY},
    VIEWER: {DASHBOARD_READ},
}


def permissions(role: str | None) -> set[str]:
    return _MATRICE.get(role or "", set())


def _csv(value: str) -> set[str]:
    return {v.strip().lower() for v in value.split(",") if v.strip()}


def role_from_groups(groups) -> str | None:
    """Rôle déduit des groupes du fournisseur d'identité.

    Le plus fort l'emporte : appartenir au groupe des administrateurs
    prime sur celui des observateurs."""
    if isinstance(groups, str):
        groups = [groups]
    revendiques = {str(g).lower() for g in (groups or [])}
    for role, configures in (
        (ADMIN, _csv(settings.oidc_admin_groups)),
        (AUDITOR, _csv(settings.oidc_auditor_groups)),
        (VIEWER, _csv(settings.oidc_viewer_groups)),
    ):
        if configures and revendiques & configures:
            return role
    return None


def default_sso_role() -> str:
    """Rôle des comptes autorisés par le SSO mais sans groupe reconnu.

    Volontairement le plus faible : un compte valide ne doit pas hériter
    de droits d'administration parce que la configuration des groupes est
    incomplète."""
    return VIEWER


def _role_depuis_les_jetons(x_admin_token: str | None,
                            x_dashboard_token: str | None) -> str | None:
    if x_admin_token and secrets.compare_digest(
            x_admin_token, settings.effective_admin_token):
        return ADMIN
    if (settings.dashboard_token and x_dashboard_token
            and secrets.compare_digest(x_dashboard_token,
                                       settings.dashboard_token)):
        return VIEWER
    # Sans token de dashboard ni SSO, la console de LECTURE reste ouverte
    # (mode démonstration, comportement historique). On accorde le rôle le
    # plus faible et jamais davantage : les opérations d'administration
    # continuent d'exiger le jeton admin, même sur une installation de
    # démonstration.
    if not settings.dashboard_token and not settings.sso_enabled:
        return VIEWER
    return None


def resolve(request: Request, x_admin_token: str | None = None,
            x_dashboard_token: str | None = None) -> tuple[str | None, dict]:
    """Rôle de l'appelant et identité associée."""
    from . import sso
    session = sso.read_session(request.cookies.get(sso.SESSION_COOKIE))
    if session:
        return session.get("role") or default_sso_role(), session
    role = _role_depuis_les_jetons(x_admin_token, x_dashboard_token)
    return role, {}


def require(permission: str):
    """Dépendance FastAPI exigeant une permission.

    Usage : `dependencies=[Depends(rbac.require(rbac.KEYS_MANAGE))]`"""
    async def _verifier(
            request: Request,
            x_admin_token: str | None = Header(default=None),
            x_dashboard_token: str | None = Header(default=None)) -> str:
        role, identite = resolve(request, x_admin_token, x_dashboard_token)
        if role is None:
            raise HTTPException(
                status_code=401,
                detail="Authentification requise (session SSO ou jeton)")
        if permission not in permissions(role):
            _log.warning("permission refusee", extra={
                "event": "rbac_denied", "role": role,
                "permission": permission,
                "subject": identite.get("email")})
            raise HTTPException(
                status_code=403,
                detail=f"Le role « {role} » n'a pas la permission "
                       f"« {permission} »")
        return role
    return _verifier


def authorize_body_token(request: Request, body_token: str,
                         permission: str) -> str:
    """Endpoints historiques qui portent le jeton admin dans le corps.

    On accepte les deux voies : le jeton (automatisation, compatibilite)
    ou une session dont le role possede la permission. Sans ca, la
    console devrait redemander le jeton admin a chaque action — et les
    utilisateurs finiraient par le coller dans un onglet."""
    if body_token and secrets.compare_digest(
            body_token, settings.effective_admin_token):
        return ADMIN
    role, identite = resolve(request)
    if role and permission in permissions(role):
        return role
    if role:
        _log.warning("permission refusee", extra={
            "event": "rbac_denied", "role": role, "permission": permission,
            "subject": identite.get("email")})
        raise HTTPException(
            status_code=403,
            detail=f"Le role {role} n'a pas la permission {permission}")
    raise HTTPException(status_code=403, detail="Token admin invalide")
