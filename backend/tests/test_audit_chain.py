from __future__ import annotations
import pytest
from app.audit.chain import append, verify_integrity, _CHAIN, _GENESIS


class TestAuditChain:
    def test_chaine_vide_integre(self):
        assert verify_integrity() is True

    def test_une_entree_integre(self):
        append("TOKENIZE", "IBAN", "IBAN:0", {"confidence": 0.99})
        assert verify_integrity() is True

    def test_plusieurs_entrees_integres(self):
        append("TOKENIZE", "IBAN", "IBAN:0", {"confidence": 0.99})
        append("BLOCK", "SECRET", "SECRET:10", {"confidence": 1.0})
        append("TOKENIZE", "PERSON", "PERSON:20", {"confidence": 0.85})
        assert verify_integrity() is True

    def test_alteration_hash_detectee(self):
        append("TOKENIZE", "IBAN", "IBAN:0", {"confidence": 0.99})
        append("BLOCK", "SECRET", "SECRET:10", {"confidence": 1.0})
        _CHAIN[0]["hash"] = "0" * 64
        assert verify_integrity() is False

    def test_alteration_prev_hash_detectee(self):
        append("TOKENIZE", "IBAN", "IBAN:0", {"confidence": 0.99})
        append("BLOCK", "SECRET", "SECRET:10", {"confidence": 1.0})
        _CHAIN[1]["prev_hash"] = "0" * 64
        assert verify_integrity() is False

    def test_alteration_payload_detectee(self):
        append("TOKENIZE", "IBAN", "IBAN:0", {"confidence": 0.99})
        _CHAIN[0]["action"] = "ALLOW"
        assert verify_integrity() is False

    def test_entree_retournee(self):
        entry = append("TOKENIZE", "IBAN", "IBAN:0", {"confidence": 0.99})
        assert "hash" in entry
        assert "prev_hash" in entry
        assert entry["prev_hash"] == _GENESIS
        assert len(entry["hash"]) == 64

    def test_chaining_prev_hash(self):
        e1 = append("TOKENIZE", "IBAN", "IBAN:0", {"confidence": 0.99})
        e2 = append("BLOCK", "SECRET", "SECRET:10", {"confidence": 1.0})
        assert e2["prev_hash"] == e1["hash"]

    def test_reset_entre_tests(self):
        assert len(_CHAIN) == 0
