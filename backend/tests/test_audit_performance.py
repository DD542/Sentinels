"""
Tests du cout de verification du journal d'audit.

Contexte : verify_integrity() etait appelee A CHAQUE requete et relisait
tout le journal. Mesure avant correction : 9 ms a 1 000 entrees, 86 ms a
10 000, 5 SECONDES a 100 000. Avec 200 employes generant ~10 000 entrees
par jour, le produit devenait inutilisable en une dizaine de jours.

Ces tests verrouillent la correction : etat en O(1) sur le chemin des
requetes, verification incrementale pour le controle courant,
verification complete reservee a l'audit.
"""
from __future__ import annotations
import time

import pytest

from app.audit import chain


def _remplir(n: int) -> None:
    for i in range(n):
        chain.append("TOKENIZE", "PERSON", f"PERSON:{i}",
                     {"value": "Jean Dupont"}, subject="Jean Dupont")


class TestCoutConstant:
    def test_etat_independant_de_la_taille(self):
        """Le chemin des requetes ne doit plus dependre de l'historique."""
        _remplir(200)
        t0 = time.perf_counter()
        for _ in range(1000):
            chain.integrity_status()
        petit = time.perf_counter() - t0

        _remplir(20_000)
        t0 = time.perf_counter()
        for _ in range(1000):
            chain.integrity_status()
        grand = time.perf_counter() - t0

        # 100x plus d'entrees ne doit pas couter sensiblement plus cher.
        assert grand < petit * 5, f"petit={petit:.4f}s grand={grand:.4f}s"

    def test_tete_et_compte_en_o1(self):
        _remplir(5_000)
        assert chain.count() == 5_000
        assert chain.head() == chain._CHAIN[-1]["hash"]

    def test_status_expose_la_datation(self):
        """`verified` seul serait trompeur : il faut savoir QUAND."""
        etat = chain.integrity_status()
        assert etat["verified"] is True          # chaine vide : trivial
        assert etat["at"] is None if "at" in etat else True
        assert etat["verified_at"] is None       # aucun controle reel
        assert etat["scope"] == "genese"


class TestVerificationIncrementale:
    async def test_ne_controle_que_le_nouveau(self):
        _remplir(100)
        premier = await chain.verify_incremental()
        assert premier["verified"] is True
        assert premier["checked"] == 100

        _remplir(5)
        second = await chain.verify_incremental()
        assert second["checked"] == 5            # pas 105

    async def test_rien_a_verifier(self):
        _remplir(10)
        await chain.verify_incremental()
        assert (await chain.verify_incremental())["checked"] == 0

    async def test_detecte_une_alteration_recente(self):
        _remplir(10)
        await chain.verify_incremental()
        _remplir(3)
        chain._CHAIN[-1]["action"] = "ALLOW"     # falsification
        assert (await chain.verify_incremental())["verified"] is False

    async def test_le_point_de_controle_n_avance_pas_sur_echec(self):
        _remplir(5)
        chain._CHAIN[-1]["action"] = "ALLOW"
        await chain.verify_incremental()
        # Toujours en echec au controle suivant : rien n'a ete valide.
        assert (await chain.verify_incremental())["verified"] is False

    async def test_alteration_ancienne_invisible_en_incremental(self):
        """Limite ASSUMEE et documentee : l'incrementale ne relit pas le
        passe. Seule la verification complete voit cette falsification —
        c'est pourquoi elle repasse periodiquement."""
        _remplir(50)
        await chain.verify_incremental()          # tout est au point de controle
        chain._CHAIN[0]["action"] = "ALLOW"       # falsification ancienne

        assert (await chain.verify_incremental())["verified"] is True
        assert await chain.verify_integrity_async() is False


class TestVerificationComplete:
    async def test_met_a_jour_l_etat(self):
        _remplir(20)
        assert await chain.verify_integrity_async() is True
        etat = chain.integrity_status()
        assert etat["verified"] is True
        assert etat["scope"] == "complete"
        assert etat["verified_at"] is not None
        assert etat["verified_entries"] == 20

    async def test_echec_propage_dans_l_etat(self):
        _remplir(10)
        chain._CHAIN[3]["action"] = "ALLOW"
        assert await chain.verify_integrity_async() is False
        assert chain.integrity_status()["verified"] is False


class TestCacheBorne:
    def test_cache_non_borne_sans_base(self):
        """Sans persistance, le cache EST la source de verite : le borner
        casserait la verification."""
        _remplir(chain._CACHE_MAX + 100)
        assert len(chain._CHAIN) == chain._CACHE_MAX + 100
        assert chain.verify_integrity() is True

    def test_compte_et_cache_distincts(self, monkeypatch):
        """Avec persistance, le cache est borne mais le compte reste juste."""
        from app import db
        monkeypatch.setattr(db, "is_enabled", lambda: True)
        _remplir(chain._CACHE_MAX + 250)
        assert len(chain._CHAIN) == chain._CACHE_MAX      # fenetre bornee
        assert chain.count() == chain._CACHE_MAX + 250    # compte exact
