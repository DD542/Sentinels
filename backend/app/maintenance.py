"""
Maintenance périodique — application EFFECTIVE des durées de conservation.

Une durée de rétention qu'on annonce sans jamais l'appliquer est une
non-conformité (RGPD art. 5(1)(e)) : ce module fait le travail réel.

Deux opérations, volontairement dissymétriques :

* **Vault** — les tokens expirés sont *supprimés*. Ils n'ont qu'une valeur
  fonctionnelle (restaurer une valeur dans une réponse), aucune valeur
  probante : passé le TTL, ils n'ont plus de raison d'exister.

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

from .config import get_settings
from .audit import chain
from .vault import fpe
from . import logs

settings = get_settings()
_log = logs.get_logger("maintenance")

_task: asyncio.Task | None = None


async def run_once() -> dict:
    """Une passe de maintenance. Sans base, tout est no-op."""
    vault_deleted = await fpe.purge_expired()
    audit_entities = await chain.purge_expired_keys(
        settings.audit_retention_days)
    result = {"vault_tokens_deleted": vault_deleted,
              "audit_entities_shredded": audit_entities}
    if vault_deleted or audit_entities:
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
