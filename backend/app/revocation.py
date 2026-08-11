"""
Révocation des sessions du dashboard.

Le cookie de session est autoportant : il porte sa propre validité, ce
qui évite un aller-retour en base à chaque requête. Revers de la
médaille — sans registre de révocation, une session ne peut pas être
coupée avant son expiration. Concrètement : un cookie volé reste
utilisable, et « se déconnecter » ne fait que l'effacer du navigateur du
propriétaire, pas de celui du voleur.

Ce module ajoute le registre manquant, avec trois portées :

* **session** (`jti`) — coupe une session précise. C'est ce qu'utilise la
  déconnexion : le cookie devient inutilisable, y compris pour qui en
  aurait gardé une copie.
* **personne** (`sub` ou adresse) — coupe toutes les sessions d'un compte
  ouvertes *avant* la révocation. Départ d'un employé, compte compromis.
* **globale** — coupe tout. Réservé à l'incident : rotation de clé,
  suspicion de fuite.

Le registre reste borné : une révocation ne sert plus à rien une fois
que la session qu'elle vise aurait expiré de toute façon, la passe de
maintenance les efface.
"""
from __future__ import annotations
import time

from . import db
from . import logs

_log = logs.get_logger("revocation")

# Caches mémoire (source de vérité si pas de base).
_REVOKED_JTI: dict[str, float] = {}       # identifiant de session -> instant
_REVOKED_SUBJECT: dict[str, float] = {}   # sub ou adresse -> instant
_GLOBAL_EPOCH: float = 0.0                # toute session émise avant est morte


def is_revoked(session: dict) -> bool:
    """Vrai si la session ne doit plus être acceptée."""
    if not session:
        return False
    if session.get("jti") in _REVOKED_JTI:
        return True

    emise = float(session.get("iat", 0))
    if emise < _GLOBAL_EPOCH:
        return True
    # Le compte est révocable par son identifiant technique comme par son
    # adresse : l'administrateur connaît rarement le `sub` du fournisseur.
    for identifiant in (session.get("sub"), session.get("email")):
        if not identifiant:
            continue
        instant = _REVOKED_SUBJECT.get(str(identifiant).lower())
        if instant is not None and emise < instant:
            return True
    return False


async def _persist(scope: str, value: str, instant: float) -> None:
    if not db.is_enabled():
        return
    try:
        async with db.pool().acquire() as con:
            await con.execute(
                "INSERT INTO session_revocations (scope, value, revoked_at) "
                "VALUES ($1, $2, $3) ON CONFLICT (scope, value) "
                "DO UPDATE SET revoked_at = EXCLUDED.revoked_at",
                scope, value, instant)
    except Exception as e:
        _log.warning("ecriture revocation echouee", extra={
            "event": "db_error", "op": "revoke", "scope": scope,
            "error": f"{type(e).__name__}: {e}"})


async def revoke_session(jti: str) -> None:
    """Coupe une session précise (déconnexion, cookie suspect)."""
    if not jti:
        return
    instant = time.time()
    _REVOKED_JTI[jti] = instant
    await _persist("jti", jti, instant)


async def revoke_subject(identifiant: str) -> None:
    """Coupe toutes les sessions d'un compte ouvertes avant maintenant."""
    cle = str(identifiant).lower()
    instant = time.time()
    _REVOKED_SUBJECT[cle] = instant
    await _persist("subject", cle, instant)
    _log.info("sessions d'un compte revoquees", extra={"event": "revoke_subject"})


async def revoke_all() -> None:
    """Coupe toutes les sessions en cours (incident, rotation de clé)."""
    global _GLOBAL_EPOCH
    _GLOBAL_EPOCH = time.time()
    await _persist("global", "*", _GLOBAL_EPOCH)
    _log.warning("toutes les sessions revoquees", extra={"event": "revoke_all"})


async def load_from_db() -> None:
    """Recharge le registre au démarrage : sans ça, un redémarrage
    ressusciterait toutes les sessions révoquées."""
    global _GLOBAL_EPOCH
    if not db.is_enabled():
        return
    try:
        async with db.pool().acquire() as con:
            lignes = await con.fetch(
                "SELECT scope, value, revoked_at FROM session_revocations")
    except Exception as e:
        _log.warning("rechargement des revocations impossible", extra={
            "event": "db_error", "op": "load_revocations",
            "error": f"{type(e).__name__}: {e}"})
        return

    _REVOKED_JTI.clear()
    _REVOKED_SUBJECT.clear()
    _GLOBAL_EPOCH = 0.0
    for r in lignes:
        instant = float(r["revoked_at"])
        if r["scope"] == "jti":
            _REVOKED_JTI[r["value"]] = instant
        elif r["scope"] == "subject":
            _REVOKED_SUBJECT[r["value"]] = instant
        elif r["scope"] == "global":
            _GLOBAL_EPOCH = max(_GLOBAL_EPOCH, instant)
    if lignes:
        _log.info("revocations rechargees", extra={
            "event": "revocations_loaded", "entries": len(lignes)})


async def purge_expired(session_ttl_hours: int) -> int:
    """Efface les révocations devenues inutiles : la session visée aurait
    expiré d'elle-même. Empêche le registre de croître sans fin."""
    limite = time.time() - session_ttl_hours * 3600
    supprimes = [j for j, t in _REVOKED_JTI.items() if t < limite]
    for j in supprimes:
        del _REVOKED_JTI[j]
    perimes_sujets = [s for s, t in _REVOKED_SUBJECT.items() if t < limite]
    for s in perimes_sujets:
        del _REVOKED_SUBJECT[s]
    total = len(supprimes) + len(perimes_sujets)

    if db.is_enabled():
        try:
            async with db.pool().acquire() as con:
                resultat = await con.execute(
                    "DELETE FROM session_revocations "
                    "WHERE scope <> 'global' AND revoked_at < $1", limite)
            total = int(resultat.split()[-1]) if resultat else total
        except Exception as e:
            _log.warning("purge des revocations echouee", extra={
                "event": "db_error", "op": "purge_revocations",
                "error": f"{type(e).__name__}: {e}"})
    return total


def _reset() -> None:
    """Remise à zéro — utilisée par les tests."""
    global _GLOBAL_EPOCH
    _REVOKED_JTI.clear()
    _REVOKED_SUBJECT.clear()
    _GLOBAL_EPOCH = 0.0
