"""
Tests de la persistance du corpus L3.

Regression couverte : le corpus vivait uniquement en memoire. Apres un
redemarrage, la protection contre la fuite de propriete intellectuelle
etait inactive SANS AUCUN SIGNAL — les extraits de documents
confidentiels repartaient chez le fournisseur d'IA.

Garantie verifiee ici : on ne persiste que des empreintes non
reversibles, jamais le texte des documents.
"""
from __future__ import annotations
import pytest

from app import db
from app.detection import l3_semantic as l3

DOC = ("Le montant total de la prestation s eleve a quatre cent cinquante "
       "mille euros hors taxes payable en douze echeances trimestrielles "
       "selon les conditions generales de vente applicables au territoire "
       "metropolitain.")
EXCERPT = ("Le montant total de la prestation s eleve a quatre cent "
           "cinquante mille euros hors taxes payable en douze echeances "
           "trimestrielles")


class _FakeCon:
    def __init__(self, store: dict):
        self.store = store

    async def executemany(self, query: str, rows):
        if "INSERT INTO corpus_shingles" in query:
            for client_id, shingle, doc_id in rows:
                self.store["shingles"][(client_id, shingle)] = doc_id
        elif "INSERT INTO corpus_chunks" in query:
            for client_id, doc_id, vec in rows:
                self.store["chunks"].append(
                    {"client_id": client_id, "doc_id": doc_id, "vec": vec})

    async def execute(self, query: str, *args):
        if "DELETE FROM corpus_chunks" in query:
            client_id, doc_id = args
            self.store["chunks"] = [
                c for c in self.store["chunks"]
                if not (c["client_id"] == client_id and c["doc_id"] == doc_id)]
        elif "DELETE FROM corpus_shingles" in query:
            client_id, doc_id = args
            for key, d in list(self.store["shingles"].items()):
                if key[0] == client_id and d == doc_id:
                    del self.store["shingles"][key]
        return ""

    async def fetch(self, query: str, *args):
        if "FROM corpus_shingles" in query:
            return [{"client_id": c, "shingle": s, "doc_id": d}
                    for (c, s), d in self.store["shingles"].items()]
        if "FROM corpus_chunks" in query:
            return list(self.store["chunks"])
        return []


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
    store = {"shingles": {}, "chunks": []}
    monkeypatch.setattr(db, "is_enabled", lambda: True)
    monkeypatch.setattr(db, "pool", lambda: _FakePool(store))
    return store


class TestCorpusPersistence:
    async def test_protection_survit_au_redemarrage(self, fake_db):
        """Le bug corrige : sans persistance, le corpus disparaissait."""
        l3.ingest_document("contrat-2026", DOC, client_id="acme")
        await l3.persist_document("contrat-2026", client_id="acme")
        assert l3.scan_sync(EXCERPT, client_id="acme")     # protege

        l3._SHINGLE_INDEX.clear()                          # redemarrage
        l3._DOC_CHUNKS.clear()
        assert l3.scan_sync(EXCERPT, client_id="acme") == []

        await l3.load_corpus_from_db()
        assert l3.scan_sync(EXCERPT, client_id="acme")     # protege a nouveau

    async def test_aucun_texte_persiste(self, fake_db):
        """Seules des empreintes non reversibles partent en base."""
        l3.ingest_document("contrat-2026", DOC, client_id="acme")
        await l3.persist_document("contrat-2026", client_id="acme")

        blob = repr(fake_db)
        for mot in ("quatre cent cinquante", "prestation", "trimestrielles"):
            assert mot not in blob

    async def test_isolation_multi_tenant_preservee(self, fake_db):
        """Apres rechargement, le corpus d'un client ne fuit pas chez l'autre."""
        l3.ingest_document("contrat-a", DOC, client_id="client-a")
        await l3.persist_document("contrat-a", client_id="client-a")
        l3._SHINGLE_INDEX.clear()
        await l3.load_corpus_from_db()

        assert l3.scan_sync(EXCERPT, client_id="client-a")
        assert l3.scan_sync(EXCERPT, client_id="client-b") == []

    async def test_forget_document(self, fake_db):
        l3.ingest_document("contrat-2026", DOC, client_id="acme")
        await l3.persist_document("contrat-2026", client_id="acme")

        removed = await l3.forget_document("contrat-2026", client_id="acme")
        assert removed > 0
        assert l3.scan_sync(EXCERPT, client_id="acme") == []
        assert fake_db["shingles"] == {}

        # Et le document ne revient pas apres un rechargement.
        await l3.load_corpus_from_db()
        assert l3.scan_sync(EXCERPT, client_id="acme") == []

    async def test_reingestion_ne_duplique_pas(self, fake_db):
        l3.ingest_document("contrat-2026", DOC, client_id="acme")
        await l3.persist_document("contrat-2026", client_id="acme")
        n1 = len(fake_db["shingles"])
        await l3.persist_document("contrat-2026", client_id="acme")
        assert len(fake_db["shingles"]) == n1


class TestBigintConversion:
    def test_aller_retour_uint64(self):
        """Les empreintes blake2b sont des uint64 ; un BIGINT Postgres est
        signe. La conversion doit etre exacte aux bornes."""
        for value in (0, 1, (1 << 63) - 1, 1 << 63, (1 << 64) - 1):
            assert l3._from_db(l3._to_db(value)) == value
            assert -(1 << 63) <= l3._to_db(value) < (1 << 63)


class TestWithoutDb:
    async def test_persist_noop_sans_base(self):
        l3.ingest_document("doc", DOC, client_id="acme")
        assert await l3.persist_document("doc", client_id="acme") == 0

    async def test_load_noop_sans_base(self):
        assert await l3.load_corpus_from_db() == 0
