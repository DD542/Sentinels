"""
Tests de la relecture du vault depuis la base.

Regression couverte : le cache memoire est LOCAL au process. Avant
correction, la table `vault` etait ecrite mais jamais relue — apres un
redemarrage (ou avec plusieurs workers), l'employe recevait le token
factice au lieu de sa vraie valeur, silencieusement.
"""
from __future__ import annotations
import pytest

from app import db
from app.vault import fpe
from app.detection.types import EntityType

IBAN = "FR7610107001011234567890129"


class _FakeCon:
    """Reproduit le contrat asyncpg utilise par le vault."""

    def __init__(self, store: dict):
        self.store = store

    async def execute(self, query: str, *args):
        if "INSERT INTO vault" in query:
            client_id, token, cipher, etype, expires = args
            self.store[token] = {"client_id": client_id, "cipher": cipher,
                                 "entity_type": etype, "expired": False}
            return "INSERT 0 1"
        if "DELETE FROM vault" in query:
            expired = [t for t, r in self.store.items() if r["expired"]]
            for t in expired:
                del self.store[t]
            return f"DELETE {len(expired)}"
        return ""

    async def fetch(self, query: str, *args):
        if "SELECT token, cipher, entity_type FROM vault" in query:
            # La requete filtre sur client_id ET expires_at > now()
            client_id = args[0] if args else None
            return [{"token": t, "cipher": r["cipher"],
                     "entity_type": r["entity_type"]}
                    for t, r in self.store.items()
                    if not r["expired"] and r.get("client_id") == client_id]
        return []

    async def fetchrow(self, query: str, *args):
        return None


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
    store: dict[str, dict] = {}
    monkeypatch.setattr(db, "is_enabled", lambda: True)
    monkeypatch.setattr(db, "pool", lambda: _FakePool(store))
    return store


class TestVaultReload:
    async def test_restauration_apres_redemarrage(self, fake_db):
        """Le bug corrige : cache memoire vide, mais la valeur est en base."""
        token = await fpe.tokenize_async(IBAN, EntityType.IBAN)
        reponse = f"Le virement vers {token} est programme."

        fpe._REVERSE_MAP.clear()          # simule redemarrage / autre worker
        restaure = await fpe.detokenize_async(reponse)
        assert IBAN in restaure
        assert token not in restaure

    async def test_valeur_stockee_chiffree(self, fake_db):
        token = await fpe.tokenize_async(IBAN, EntityType.IBAN)
        cipher = fake_db[token]["cipher"]
        assert IBAN not in cipher
        assert db.decrypt(cipher, fpe.DEFAULT_CLIENT) == IBAN

    async def test_token_expire_non_restaure(self, fake_db):
        """Passe la retention : la valeur n'est plus restaurable."""
        token = await fpe.tokenize_async(IBAN, EntityType.IBAN)
        fake_db[token]["expired"] = True
        fpe._REVERSE_MAP.clear()

        restaure = await fpe.detokenize_async(f"virement vers {token}")
        assert IBAN not in restaure

    async def test_purge_supprime_les_expires(self, fake_db):
        t1 = await fpe.tokenize_async(IBAN, EntityType.IBAN)
        t2 = await fpe.tokenize_async("FR7630001007941234567890185",
                                      EntityType.IBAN)
        fake_db[t1]["expired"] = True

        assert await fpe.purge_expired() == 1
        assert t1 not in fake_db          # retention reellement appliquee
        assert t2 in fake_db

    async def test_cache_memoire_prime(self, fake_db):
        """Le cache local est toujours pris en compte, base indisponible ou non."""
        token = await fpe.tokenize_async(IBAN, EntityType.IBAN)
        fake_db.clear()                   # base videe, cache intact
        assert IBAN in await fpe.detokenize_async(f"vers {token}")


class TestWithoutDb:
    async def test_pas_de_base_pas_de_candidats(self):
        assert await fpe._db_candidates() == {}

    async def test_purge_noop_sans_base(self):
        assert await fpe.purge_expired() == 0
