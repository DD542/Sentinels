"""
Tests de la maintenance periodique (application des durees de conservation).

Point de conception verifie ici : la purge du journal d'audit ne supprime
JAMAIS d'entree — elle detruit les cles. La chaine reste verifiable de
bout en bout (AI Act art. 26(6)) pendant que le detail devient illisible
(RGPD art. 5(1)(e)).
"""
from __future__ import annotations
import asyncio
import time
from contextlib import contextmanager

import pytest

from app import db, maintenance
from app.audit import chain, crypto
from app.config import get_settings

settings = get_settings()
DAY = 86400


class _FakeCon:
    def __init__(self, store: dict):
        self.store = store

    async def fetch(self, query: str, *args):
        if "DELETE FROM audit_keys" in query and "RETURNING" in query:
            cutoff = args[0]
            # Entites dont la DERNIERE entree depasse la retention.
            last_seen: dict[str, float] = {}
            for e in chain._CHAIN:
                last_seen[e["entity_id"]] = max(
                    last_seen.get(e["entity_id"], 0), e["ts"])
            expired = [eid for eid, ts in last_seen.items()
                       if ts < cutoff and eid in self.store["keys"]]
            for eid in expired:
                del self.store["keys"][eid]
            return [{"entity_id": eid} for eid in expired]
        return []

    async def fetchrow(self, query: str, *args):
        if "SELECT wrapped" in query:
            wrapped = self.store["keys"].get(args[0])
            return {"wrapped": wrapped} if wrapped else None
        if "INSERT INTO audit_keys" in query:
            entity_id, wrapped = args
            if entity_id in self.store["keys"]:
                return None
            self.store["keys"][entity_id] = wrapped
            return {"wrapped": wrapped}
        return None

    async def execute(self, query: str, *args):
        if "DELETE FROM vault" in query:
            expired = [t for t, r in self.store["vault"].items() if r["expired"]]
            for t in expired:
                del self.store["vault"][t]
            return f"DELETE {len(expired)}"
        return ""


class _FakePool:
    def __init__(self, store: dict):
        self.store = store

    def acquire(self):
        con = _FakeCon(self.store)

        class _Ctx:
            async def __aenter__(self_):
                return con

            async def __aexit__(self_, *exc):
                return False

        return _Ctx()


@pytest.fixture
def fake_db(monkeypatch):
    store = {"keys": {}, "vault": {}}
    monkeypatch.setattr(db, "is_enabled", lambda: True)
    monkeypatch.setattr(db, "pool", lambda: _FakePool(store))
    return store


class _FrozenClock:
    def __init__(self, moment: float):
        self._moment = moment

    def time(self) -> float:
        return self._moment


@contextmanager
def _il_y_a(days: float):
    """Ecrit les entrees AVEC un horodatage ancien.

    On ne peut pas vieillir une entree apres coup : le `ts` fait partie
    du scellement, le modifier casse l'integrite (c'est exactement ce
    que la chaine protege). Il faut donc reculer l'horloge a l'ecriture."""
    real = chain.time
    chain.time = _FrozenClock(time.time() - days * DAY)
    try:
        yield
    finally:
        chain.time = real


class TestAuditRetention:
    async def test_cle_detruite_hors_retention(self, fake_db):
        with _il_y_a(400):
            entry = await chain.append_async("TOKENIZE", "PERSON", "PERSON:0",
                                             {"value": "Jean Dupont"})
        assert chain.read_detail(entry) == {"value": "Jean Dupont"}

        assert await chain.purge_expired_keys(retention_days=365) == 1
        # Donnee illisible...
        assert chain.read_detail(entry) is None
        # ...mais l'entree existe toujours et la chaine reste verifiable.
        assert len(chain._CHAIN) == 1
        assert chain.verify_integrity() is True

    async def test_entree_recente_conservee(self, fake_db):
        entry = await chain.append_async("TOKENIZE", "IBAN", "IBAN:0",
                                         {"value": "FR76"})
        assert await chain.purge_expired_keys(retention_days=365) == 0
        assert chain.read_detail(entry) == {"value": "FR76"}

    async def test_retention_illimitee_ne_purge_rien(self, fake_db):
        with _il_y_a(4000):
            await chain.append_async("TOKENIZE", "PERSON", "PERSON:0",
                                     {"value": "A"})
        assert await chain.purge_expired_keys(retention_days=0) == 0

    async def test_identifiant_reutilisable_apres_purge(self, fake_db):
        """Les identifiants d'entite (« IBAN:12 ») se repetent d'un prompt
        a l'autre : une purge de retention ne doit pas priver de cle les
        donnees futures."""
        with _il_y_a(400):
            old = await chain.append_async("TOKENIZE", "PERSON", "PERSON:0",
                                           {"value": "ancien"})
        await chain.purge_expired_keys(retention_days=365)

        new = await chain.append_async("TOKENIZE", "PERSON", "PERSON:0",
                                       {"value": "nouveau"})
        assert chain.read_detail(new) == {"value": "nouveau"}   # lisible
        assert chain.read_detail(old) is None                   # toujours purge
        assert chain.verify_integrity() is True

    async def test_sans_base_pas_de_purge(self):
        await chain.append_async("TOKENIZE", "PERSON", "PERSON:0", {"value": "A"})
        assert await chain.purge_expired_keys(retention_days=1) == 0


class TestMaintenanceLoop:
    async def test_run_once_agrege_les_deux_purges(self, fake_db, monkeypatch):
        monkeypatch.setattr(settings, "audit_retention_days", 365)
        fake_db["vault"]["tok-1"] = {"expired": True}
        fake_db["vault"]["tok-2"] = {"expired": False}
        with _il_y_a(400):
            await chain.append_async("TOKENIZE", "PERSON", "PERSON:0",
                                     {"value": "A"})

        result = await maintenance.run_once()
        assert result["vault_tokens_deleted"] == 1
        assert result["audit_entities_shredded"] == 1
        assert "revocations_purged" in result   # troisieme stock purge
        assert "tok-2" in fake_db["vault"]

    async def test_start_stop_idempotents(self, monkeypatch):
        monkeypatch.setattr(settings, "purge_interval_minutes", 60)
        maintenance.start()
        first = maintenance._task
        maintenance.start()                       # ne relance pas
        assert maintenance._task is first
        await maintenance.stop()
        assert maintenance._task is None
        await maintenance.stop()                  # sans effet

    async def test_intervalle_nul_desactive(self, monkeypatch):
        monkeypatch.setattr(settings, "purge_interval_minutes", 0)
        maintenance.start()
        assert maintenance._task is None

    async def test_boucle_survit_a_une_erreur(self, monkeypatch):
        """Une passe qui echoue ne doit pas tuer la maintenance."""
        calls = {"n": 0}

        async def _boom():
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("base indisponible")
            return {}

        monkeypatch.setattr(maintenance, "run_once", _boom)
        task = asyncio.create_task(maintenance._loop(0))
        for _ in range(20):
            await asyncio.sleep(0)
            if calls["n"] >= 2:
                break
        task.cancel()
        assert calls["n"] >= 2                    # a repris apres l'erreur
