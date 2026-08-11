"""
Politique de détection par client.

Le faux positif coûte plus cher que le faux négatif. Si SENTINEL
tokenise le nom de votre société parce qu'il ressemble à un nom de
personne, la réponse du modèle devient absurde, l'employé conclut que
l'outil casse son travail — et le contourne. Une protection contournée
ne protège rien.

Trois leviers, cloisonnés par client :

* **liste d'exceptions** — des valeurs qui ne doivent jamais être
  interceptées (raison sociale, noms de produits, mots métier) ;
* **seuil de confiance par type** — relever le seuil sur les noms sans
  toucher aux IBAN ;
* **action par type** — laisser passer, tokeniser ou bloquer.

Deux garde-fous, parce qu'un réglage est aussi une façon d'affaiblir un
contrôle de sécurité :

1. **Toute modification est scellée dans le journal d'audit.** Baisser sa
   protection est un droit ; le faire discrètement, non.
2. **Une politique dégradée est signalée dans le rapport de conformité**
   (secrets ou fuites documentaires laissés passer). Le DPO le voit.
"""
from __future__ import annotations
import json

from .audit import subjects
from .detection.types import Action, EntityType
from . import db
from . import logs

_log = logs.get_logger("policy")

DEFAULT_CLIENT = "default"

# client_id -> politique
_POLICIES: dict[str, dict] = {}

# Types dont l'abandon dégrade réellement la posture : on l'autorise
# (le client est souverain) mais le rapport de conformité le dira.
_TYPES_CRITIQUES = {EntityType.SECRET.value, EntityType.IP_LEAK.value}

_ACTIONS_VALIDES = {a.value for a in Action}
_TYPES_VALIDES = {t.value for t in EntityType}


def empty_policy() -> dict:
    return {"allowlist": [], "min_confidence": {}, "actions": {},
            "deep_scan": False}


def get(client_id: str = DEFAULT_CLIENT) -> dict:
    return _POLICIES.get(client_id) or empty_policy()


# ============================================================
# Validation
# ============================================================

def validate(policy: dict) -> dict:
    """Normalise et valide une politique. Lève ValueError si elle est
    incohérente — mieux vaut refuser un réglage que l'appliquer de
    travers sur un contrôle de sécurité."""
    if not isinstance(policy, dict):
        raise ValueError("La politique doit être un objet")

    allowlist = policy.get("allowlist") or []
    if not isinstance(allowlist, list):
        raise ValueError("`allowlist` doit être une liste de valeurs")
    if len(allowlist) > 1000:
        raise ValueError("`allowlist` limitée à 1000 entrées")
    allowlist = [str(v).strip() for v in allowlist if str(v).strip()]

    seuils = policy.get("min_confidence") or {}
    if not isinstance(seuils, dict):
        raise ValueError("`min_confidence` doit être un objet type -> seuil")
    for t, v in seuils.items():
        if t not in _TYPES_VALIDES:
            raise ValueError(f"Type inconnu dans `min_confidence` : {t}")
        if not isinstance(v, (int, float)) or not 0.0 <= float(v) <= 1.0:
            raise ValueError(f"Seuil hors de [0, 1] pour {t}")

    actions = policy.get("actions") or {}
    if not isinstance(actions, dict):
        raise ValueError("`actions` doit être un objet type -> action")
    for t, a in actions.items():
        if t not in _TYPES_VALIDES:
            raise ValueError(f"Type inconnu dans `actions` : {t}")
        if a not in _ACTIONS_VALIDES:
            raise ValueError(
                f"Action inconnue pour {t} : {a} "
                f"(attendu : {', '.join(sorted(_ACTIONS_VALIDES))})")

    deep = policy.get("deep_scan", False)
    if not isinstance(deep, bool):
        raise ValueError("`deep_scan` doit etre un booleen")

    return {
        "allowlist": allowlist,
        "min_confidence": {t: float(v) for t, v in seuils.items()},
        "actions": dict(actions),
        "deep_scan": deep,
    }


def degradations(policy: dict) -> list[str]:
    """Réglages qui affaiblissent la posture, pour le rapport de
    conformité. Ce n'est pas un blocage : c'est une mise en visibilité."""
    alertes = []
    for t, a in (policy.get("actions") or {}).items():
        if t in _TYPES_CRITIQUES and a == Action.ALLOW.value:
            alertes.append(f"{t} laissé passer sans blocage")
    for t, seuil in (policy.get("min_confidence") or {}).items():
        if seuil >= 0.95:
            alertes.append(f"seuil très élevé sur {t} ({seuil})")
    if len(policy.get("allowlist") or []) > 200:
        alertes.append(f"liste d'exceptions volumineuse "
                       f"({len(policy['allowlist'])} entrées)")
    return alertes


# ============================================================
# Application
# ============================================================

def _index_allowlist(client_id: str) -> set[str]:
    """Formes normalisées des exceptions. La normalisation est celle de
    l'index aveugle : casse, accents et séparateurs neutralisés, donc
    « Martin & Associés » couvre « martin et associes »."""
    return {subjects.normalize(v) for v in get(client_id).get("allowlist", [])
            if subjects.normalize(v)}


def filter_findings(findings: list, client_id: str = DEFAULT_CLIENT) -> tuple[list, list]:
    """Applique exceptions et seuils. Renvoie (retenus, écartés).

    La correspondance d'exception est **exacte** sur la forme
    normalisée : prévisible et auditable. Une correspondance partielle
    supprimerait silencieusement des détections voisines — inacceptable
    pour un contrôle de sécurité."""
    politique = get(client_id)
    if not politique.get("allowlist") and not politique.get("min_confidence"):
        return findings, []

    exceptions = _index_allowlist(client_id)
    seuils = politique.get("min_confidence") or {}
    retenus, ecartes = [], []
    for f in findings:
        if exceptions and subjects.normalize(f.value) in exceptions:
            ecartes.append((f, "exception"))
            continue
        seuil = seuils.get(f.entity_type.value)
        if seuil is not None and f.confidence < seuil:
            ecartes.append((f, "sous le seuil"))
            continue
        retenus.append(f)
    return retenus, ecartes


def deep_scan_enabled(client_id: str = DEFAULT_CLIENT) -> bool:
    """Le client a-t-il demande le rattrapage par juge local ?

    Desactive par defaut : une inference coute mille fois le reste du
    pipeline. C'est un choix de compromis rappel/latence, pas un
    reglage a activer partout."""
    return bool(get(client_id).get("deep_scan"))


def action_override(entity_type: EntityType,
                    client_id: str = DEFAULT_CLIENT) -> Action | None:
    """Action imposée par le client pour ce type, ou None."""
    valeur = (get(client_id).get("actions") or {}).get(entity_type.value)
    return Action(valeur) if valeur else None


# ============================================================
# Persistance
# ============================================================

async def set_policy(client_id: str, policy: dict) -> dict:
    """Enregistre la politique validée d'un client."""
    valide = validate(policy)
    _POLICIES[client_id] = valide

    if db.is_enabled():
        try:
            async with db.pool().acquire() as con:
                await con.execute(
                    "INSERT INTO client_policies (client_id, policy) "
                    "VALUES ($1, $2) ON CONFLICT (client_id) DO UPDATE SET "
                    "policy = EXCLUDED.policy, updated_at = now()",
                    client_id, json.dumps(valide, ensure_ascii=False))
        except Exception as e:
            _log.warning("ecriture politique echouee", extra={
                "event": "db_error", "op": "set_policy",
                "error": f"{type(e).__name__}: {e}"})
    return valide


async def load_from_db() -> int:
    """Recharge les politiques au démarrage : sans ça, un redémarrage
    réactiverait des détections que le client avait désactivées."""
    if not db.is_enabled():
        return 0
    try:
        async with db.pool().acquire() as con:
            lignes = await con.fetch(
                "SELECT client_id, policy FROM client_policies")
    except Exception as e:
        _log.warning("rechargement des politiques impossible", extra={
            "event": "db_error", "op": "load_policies",
            "error": f"{type(e).__name__}: {e}"})
        return 0

    _POLICIES.clear()
    for r in lignes:
        try:
            _POLICIES[r["client_id"]] = validate(json.loads(r["policy"]))
        except (ValueError, json.JSONDecodeError):
            _log.warning("politique invalide ignoree", extra={
                "event": "policy_invalid", "client": r["client_id"]})
    if lignes:
        _log.info("politiques rechargees", extra={
            "event": "policies_loaded", "clients": len(_POLICIES)})
    return len(_POLICIES)


def all_degradations() -> list[dict]:
    """Politiques affaiblies, tous clients confondus — pour le rapport de
    conformite. Aucune valeur d'exception n'est divulguee, seulement le
    fait qu'un controle a ete relache."""
    sortie = []
    for client_id, politique in _POLICIES.items():
        alertes = degradations(politique)
        if alertes:
            sortie.append({"client_id": client_id, "warnings": alertes})
    return sortie


def _reset() -> None:
    _POLICIES.clear()
