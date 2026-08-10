"""
Tests de l'index aveugle des personnes concernees (RGPD art. 15 et 17).

Ce que l'on verifie ici :
  * l'identite n'est JAMAIS stockee, seulement une reference HMAC ;
  * la reference est deterministe (on retrouve la personne) mais non
    reversible et non enumerable sans la cle ;
  * effacer une personne rend illisibles SES entrees, et rien que les
    siennes — c'est tout l'interet d'indexer par personne plutot que
    par entite technique ;
  * la chaine de hachage reste verifiable, y compris pour les entrees
    anterieures a l'index (scellees sans le champ subject_ref).
"""
from __future__ import annotations
import pytest

from app.audit import chain, crypto, subjects


class TestBlindIndex:
    def test_deterministe(self):
        assert subjects.subject_ref("Jean Dupont") == \
               subjects.subject_ref("Jean Dupont")

    def test_insensible_a_la_forme(self):
        """Casse, accents, espaces et separateurs ne doivent pas creer
        deux personnes distinctes."""
        base = subjects.subject_ref("Jean Dupont")
        for variante in ("jean dupont", "JEAN  DUPONT", "Jean Dupônt"):
            assert subjects.subject_ref(variante) == base

        iban = subjects.subject_ref("FR7610107001011234567890129")
        assert subjects.subject_ref("FR76 1010 7001 0112 3456 7890 129") == iban

    def test_personnes_differentes_references_differentes(self):
        assert subjects.subject_ref("Jean Dupont") != \
               subjects.subject_ref("Marie Curie")

    def test_non_reversible(self):
        ref = subjects.subject_ref("Jean Dupont")
        assert "jean" not in ref.lower()
        assert "dupont" not in ref.lower()

    def test_non_enumerable_sans_la_cle(self):
        """Un simple SHA-256 se casserait avec un annuaire de noms ; le
        HMAC impose de connaitre la cle d'audit."""
        import hashlib
        nu = hashlib.sha256(b"jeandupont").hexdigest()
        assert nu[:32] not in subjects.subject_ref("Jean Dupont")

    def test_valeur_vide_non_indexee(self):
        assert subjects.subject_ref("") is None
        assert subjects.subject_ref(None) is None
        assert subjects.subject_ref("!!! ---") is None   # rien d'exploitable


class TestSubjectScopedErasure:
    async def test_efface_une_personne_et_elle_seule(self):
        jean = chain.append("TOKENIZE", "PERSON", "PERSON:0",
                            {"value": "Jean Dupont"}, subject="Jean Dupont")
        marie = chain.append("TOKENIZE", "PERSON", "PERSON:0",
                             {"value": "Marie Curie"}, subject="Marie Curie")
        # Meme entite technique « PERSON:0 », deux personnes distinctes.
        assert chain.read_detail(jean) == {"value": "Jean Dupont"}
        assert chain.read_detail(marie) == {"value": "Marie Curie"}

        assert await chain.forget_subject("Jean Dupont") == 1

        assert chain.read_detail(jean) is None       # efface
        assert chain.read_detail(marie) == {"value": "Marie Curie"}  # intact
        assert chain.verify_integrity() is True

    async def test_toutes_les_entrees_de_la_personne(self):
        """Une personne vue dans plusieurs prompts, a des positions
        differentes, est effacee d'un seul coup."""
        entries = [
            chain.append("TOKENIZE", "PERSON", "PERSON:0",
                         {"value": "Jean Dupont"}, subject="Jean Dupont"),
            chain.append("TOKENIZE", "PERSON", "PERSON:42",
                         {"value": "Jean Dupont"}, subject="jean dupont"),
            chain.append("TOKENIZE", "PERSON", "PERSON:7",
                         {"value": "Jean Dupont"}, subject="JEAN DUPONT"),
        ]
        assert await chain.forget_subject("Jean Dupont") == 3
        assert all(chain.read_detail(e) is None for e in entries)

    async def test_effacement_inconnu_sans_effet(self):
        chain.append("TOKENIZE", "PERSON", "PERSON:0",
                     {"value": "Jean Dupont"}, subject="Jean Dupont")
        assert await chain.forget_subject("Personne Inexistante") == 0

    async def test_resume_par_personne(self):
        chain.append("TOKENIZE", "PERSON", "PERSON:0",
                     {"value": "Jean Dupont"}, subject="Jean Dupont")
        chain.append("TOKENIZE", "IBAN", "IBAN:5",
                     {"value": "FR76"}, subject="Jean Dupont")

        summary = await chain.subject_summary("Jean Dupont")
        assert summary["found"] is True
        assert summary["entries"] == 2
        assert summary["erased"] is False
        # Le resume ne divulgue aucune valeur.
        assert "Jean Dupont" not in repr(summary)
        assert "FR76" not in repr(summary)

        await chain.forget_subject("Jean Dupont")
        assert (await chain.subject_summary("Jean Dupont"))["erased"] is True

    async def test_resume_personne_inconnue(self):
        summary = await chain.subject_summary("Inconnu Ici")
        assert summary["found"] is False
        assert summary["entries"] == 0


class TestChainCompatibility:
    def test_entrees_sans_sujet_restent_verifiables(self):
        """Les entrees techniques (sans personne concernee) sont scellees
        sans le champ subject_ref : leur hash doit rester valide."""
        entry = chain.append("CORPUS_INGEST", "DOCUMENT", "doc-1",
                             {"shingles": 42})
        assert "subject_ref" not in entry
        assert chain.verify_integrity() is True

    def test_melange_avec_et_sans_sujet(self):
        chain.append("CORPUS_INGEST", "DOCUMENT", "doc-1", {"shingles": 1})
        chain.append("TOKENIZE", "PERSON", "PERSON:0",
                     {"value": "Jean"}, subject="Jean Dupont")
        chain.append("KEY_REVOKED", "ADMIN", "client-a", {"n": 1})
        assert chain.verify_integrity() is True

    def test_subject_ref_scelle(self):
        """Le champ est couvert par le hash : le falsifier casse la chaine
        (on ne peut pas re-router l'effacement d'une personne)."""
        entry = chain.append("TOKENIZE", "PERSON", "PERSON:0",
                             {"value": "Jean"}, subject="Jean Dupont")
        entry["subject_ref"] = subjects.subject_ref("Marie Curie")
        assert chain.verify_integrity() is False
