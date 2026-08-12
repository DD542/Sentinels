"""
Maintenance périodique — application EFFECTIVE des durées de conservation.

Une durée de rétention qu'on annonce sans jamais l'appliquer est une
non-conformité (RGPD art. 5(1)(e)) : ce module fait le travail réel.

Deux opérations, volontairement dissymétriques :

* **Vault** — les tokens expirés sont *supprimés*, en base **et dans le
  cache mémoire de chaque processus**. Ils n'ont qu'une valeur
  fonctionnelle (restaurer une valeur dans une réponse), aucune valeur
  probante : passé le TTL, ils n'ont plus de raison d'exister. Le cache
  compte autant que la base : une rétention appliquée d'un seul côté
  n'est pas appliquée.

* **Audit** — les entrées ne sont *jamais* supprimées : la chaîne de
  hachage doit rester vérifiable de bout en bout (AI Act art. 26(6)), et
  toute suppression casserait le chaînage. C'est leur clé de déchiffrement
  qui est détruite au-delà de la rétention. **On garde la preuve, on perd
  la donnée.**

La boucle tourne en tâche de fond ; elle est aussi déclenchable à la
demande via `POST /admin/maintenance/purge` (exploitation, démonstration).
"""
from __future__ import annotations
import asyncio
import time

from .config import get_settings
from .audit import chain
from .vault import fpe
from . import logs
from . import revocation

settings = get_settings()
_log = logs.get_logger("maintenance")

_task: asyncio.Task | None = None


_derniere_complete: float = 0.0


async def _verifier_journal() -> dict:
    """Incrémentale à chaque passe ; complète quand elle est due.

    L'incrémentale ne relit que les entrées récentes — son coût suit le
    trafic, pas l'historique. Mais elle ne verrait pas une altération
    ANTÉRIEURE au point de contrôle : c'est pourquoi une vérification
    complète repasse périodiquement sur tout le journal."""
    global _derniere_complete
    periode = settings.audit_full_verify_hours * 3600
    if periode and (time.time() - _derniere_complete) >= periode:
        ok = await chain.verify_integrity_async()
        _derniere_complete = time.time()
        return {"verified": ok, "checked": chain.count(), "scope": "complete"}
    return await chain.verify_incremental()


async def run_once() -> dict:
    """Une passe de maintenance. Sans base, seule l'éviction du cache
    mémoire a lieu — mais elle a lieu : le mode sans Postgres n'est pas
    dispensé de la durée de conservation."""
    vault = await fpe.purge_expired_detail()
    vault_deleted = vault["rows_deleted"]
    audit_entities = await chain.purge_expired_keys(
        settings.audit_retention_days)
    # Une revocation ne sert plus a rien quand la session visee aurait
    # expire d'elle-meme : le registre reste borne.
    revocations = await revocation.purge_expired(settings.session_ttl_hours)
    # Verification du journal : incrementale (cout proportionnel au
    # trafic recent, pas a l'historique). C'est elle qui alimente l'etat
    # rapporte en O(1) par les reponses d'API.
    controle = await _verifier_journal()
    result = {"vault_tokens_deleted": vault_deleted,
              "vault_cache_evicted": vault["cache_evicted"],
              "audit_entities_shredded": audit_entities,
              "revocations_purged": revocations,
              "audit_entries_verified": controle["checked"],
              "audit_verified": controle["verified"]}
    if (vault_deleted or vault["cache_evicted"] or audit_entities
            or controle["checked"]):
        _log.info("passe de maintenance", extra={"event": "purge", **result})
    return result


async def _loop(interval_seconds: int) -> None:
    """Boucle de fond. On dort AVANT la première passe : le démarrage a
    déjà fait la sienne, inutile de la refaire immédiatement."""
    while True:
        try:
            await asyncio.sleep(interval_seconds)
            await run_once()
        except asyncio.CancelledError:
            raise                      # arrêt propre du service
        except Exception as e:         # une passe ratée ne tue pas la boucle
            _log.warning("passe de maintenance echouee", extra={
                "event": "purge_error", "error": f"{type(e).__name__}: {e}"})


def start() -> None:
    """Démarre la maintenance périodique (idempotent)."""
    global _task
    if _task is not None and not _task.done():
        return
    if settings.purge_interval_minutes <= 0:
        _log.info("maintenance periodique desactivee",
                  extra={"event": "purge_disabled"})
        return
    _task = asyncio.create_task(_loop(settings.purge_interval_minutes * 60))


async def stop() -> None:
    """Arrête proprement la tâche de fond."""
    global _task
    if _task is None:
        return
    _task.cancel()
    try:
        await _task
    except (asyncio.CancelledError, Exception):
        pass
    _task = None
