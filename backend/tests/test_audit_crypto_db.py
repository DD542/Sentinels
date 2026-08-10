"""
Tests du keyring d'audit sur le CHEMIN BASE DE DONNEES (les autres tests
couvrent le repli memoire). Un faux pool asyncpg permet de rejouer la
logique sans Postgres, en CI comme en local.

Regression couverte : une entree ecrite en mode DB doit etre relisible
IMMEDIATEMENT. Sinon une donnee simplement non chargee serait
indiscernable d'une donnee effacee (crypto-shreddee).
"""
from __future__ import annotations
import pytest

from app import db
from app.audit import chain, crypto


class _FakeCon:
    """Reproduit le contrat asyncpg utilise par le keyring."""

    def __init__(self, store: dict):
        self.store = store

    async def fetchrow(self, query: str, *args):
        if "SELECT wrapped" in query:
            wrapped = self.store.get(args[0])
            return {"wrapped": wrapped} if wrapped else None
        if "INSERT INTO audit_keys" in query:
            entity_id, wrapped = args
            if entity_id in self.store:      # ON CONFLICT DO NOTHING
                return None
            self.store[entity_id] = wrapped
            return {"wrapped": wrapped}
        if "COUNT(*)" in query:
            return {"n": 0}
        return None

    async def execute(self, query: str, *args):
        if "DELETE FROM audit_keys" in query:
            self.store.pop(args[0], None)


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
    """Simule une persistance active ; renvoie la table audit_keys."""
    store: dict[str, str] = {}
    monkeypatch.setattr(db, "is_enabled", lambda: True)
    monkeypatch.setattr(db, "pool", lambda: _FakePool(store))
    return store


class TestKeyringDbPath:
    async def test_lecture_immediate_apres_ecriture(self, fake_db):
        """Le bug corrige : sans mise en cache de la DEK, read_detail
        renvoyait None jusqu'au redemarrage."""
        detail = {"value": "Jean Dupont", "confidence": 0.9}
        entry = await chain.append_async("TOKENIZE", "PERSON", "PERSON:0", detail)
        assert chain.read_detail(entry) == detail

    async def test_dek_persistee_enveloppee(self, fake_db):
        await chain.append_async("TOKENIZE", "IBAN", "IBAN:0", {"value": "A"})
        wrapped = fake_db["IBAN:0"]
        # Jamais la DEK en clair en base : elle est chiffree par la KEK.
        assert crypto.unwrap_key(wrapped) is not None
        assert "IBAN" not in wrapped

    async def test_meme_entite_reutilise_sa_dek(self, fake_db):
        e1 = await chain.append_async("TOKENIZE", "PERSON", "PERSON:0", {"value": "A"})
        e2 = await chain.append_async("TOKENIZE", "PERSON", "PERSON:0", {"value": "B"})
        assert len(fake_db) == 1                 # une seule cle creee
        assert chain.read_detail(e1) == {"value": "A"}
        assert chain.read_detail(e2) == {"value": "B"}

    async def test_forget_async_detruit_la_cle(self, fake_db):
        entry = await chain.append_async("TOKENIZE", "PERSON", "PERSON:0",
                                         {"value": "Jean Dupont"})
        assert chain.read_detail(entry) == {"value": "Jean Dupont"}

        await chain.forget_async("PERSON:0")
        assert "PERSON:0" not in fake_db          # cle supprimee en base
        assert chain.read_detail(entry) is None   # donnee irrecuperable
        assert chain.verify_integrity() is True   # preuve d'existence intacte
