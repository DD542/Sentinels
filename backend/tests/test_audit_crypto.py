from __future__ import annotations
import pytest

from app.audit import chain, crypto


class TestFernetEncryption:
    def test_cipher_nest_pas_du_clair(self):
        entry = chain.append("TOKENIZE", "PERSON", "PERSON:0",
                             {"value": "Jean Dupont", "confidence": 0.9})
        # La valeur sensible ne doit apparaître nulle part en clair.
        assert "Jean Dupont" not in entry["cipher"]
        assert entry["cipher"].startswith("gAAAAA")  # préfixe Fernet

    def test_dechiffrement_round_trip(self):
        detail = {"value": "FR7630001007941234567890185", "confidence": 1.0}
        entry = chain.append("TOKENIZE", "IBAN", "IBAN:0", detail)
        assert chain.read_detail(entry) == detail

    def test_cipher_non_dechiffrable_avec_mauvaise_cle(self):
        entry = chain.append("TOKENIZE", "PERSON", "PERSON:0", {"value": "X"})
        other = crypto.new_dek()
        assert crypto.decrypt_detail(entry["cipher"], other) is None

    def test_meme_entite_partage_sa_cle(self):
        e1 = chain.append("TOKENIZE", "PERSON", "PERSON:0", {"value": "A"})
        e2 = chain.append("TOKENIZE", "PERSON", "PERSON:0", {"value": "B"})
        assert chain.read_detail(e1) == {"value": "A"}
        assert chain.read_detail(e2) == {"value": "B"}

    def test_integrite_preservee_apres_chiffrement(self):
        chain.append("TOKENIZE", "PERSON", "PERSON:0", {"value": "A"})
        chain.append("BLOCK", "SECRET", "SECRET:1", {"value": "sk-xxx"})
        assert chain.verify_integrity() is True


class TestCryptoShredding:
    def test_forget_rend_illisible(self):
        entry = chain.append("TOKENIZE", "PERSON", "PERSON:0",
                             {"value": "Jean Dupont"})
        assert chain.read_detail(entry) == {"value": "Jean Dupont"}

        affected = chain.forget("PERSON:0")
        assert affected == 1
        # La donnée est désormais irrécupérable...
        assert chain.read_detail(entry) is None

    def test_forget_preserve_lintegrite(self):
        chain.append("TOKENIZE", "PERSON", "PERSON:0", {"value": "A"})
        chain.append("BLOCK", "SECRET", "SECRET:1", {"value": "B"})
        chain.forget("PERSON:0")
        # ...mais la preuve d'existence (chaîne de hachage) reste intègre.
        assert chain.verify_integrity() is True

    def test_forget_ne_recree_pas_la_cle(self):
        chain.append("TOKENIZE", "PERSON", "PERSON:0", {"value": "A"})
        chain.forget("PERSON:0")
        # Un nouvel append sur une entité oubliée ne ressuscite pas la clé.
        entry = chain.append("TOKENIZE", "PERSON", "PERSON:0", {"value": "C"})
        assert entry["cipher"] == "SHREDDED"
        assert chain.verify_integrity() is True

    def test_forget_compte_les_entrees(self):
        chain.append("TOKENIZE", "PERSON", "PERSON:0", {"value": "A"})
        chain.append("TOKENIZE", "PERSON", "PERSON:0", {"value": "B"})
        chain.append("TOKENIZE", "IBAN", "IBAN:0", {"value": "C"})
        assert chain.forget("PERSON:0") == 2


class TestKeyWrapping:
    def test_dek_stockee_enveloppee(self):
        chain.append("TOKENIZE", "PERSON", "PERSON:0", {"value": "A"})
        wrapped = crypto._KEYRING["PERSON:0"]
        # La DEK n'est jamais stockée en clair : elle est chiffrée par la KEK.
        dek = crypto.unwrap_key(wrapped)
        assert dek is not None
        assert dek != wrapped.encode()

    def test_unwrap_mauvais_token(self):
        assert crypto.unwrap_key("pas-un-token-fernet") is None
