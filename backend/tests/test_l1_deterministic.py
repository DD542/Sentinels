from __future__ import annotations
import pytest
from app.detection.l1_deterministic import scan
from app.detection.types import EntityType


class TestIBAN:
    def _find(self, text):
        return [f for f in scan(text) if f.entity_type == EntityType.IBAN]

    def test_iban_fr_valide(self):
        found = self._find("virement vers FR7610107001011234567890129")
        assert len(found) == 1
        assert found[0].value == "FR7610107001011234567890129"

    def test_iban_fr_avec_espaces(self):
        found = self._find("compte FR76 1010 7001 0112 3456 7890 129 merci")
        assert len(found) == 1

    def test_iban_fr_minuscule(self):
        found = self._find("iban : fr7610107001011234567890129")
        assert len(found) == 1

    def test_iban_de_valide(self):
        found = self._find("DE89370400440532013000")
        assert len(found) == 1

    def test_iban_gb_valide(self):
        found = self._find("GB82WEST12345698765432")
        assert len(found) == 1

    def test_iban_cle_incorrecte_rejetee(self):
        found = self._find("FR7610107001011234567890128")
        assert len(found) == 0

    def test_iban_zeros_rejete(self):
        found = self._find("FR0000000000000000000000000")
        assert len(found) == 0

    def test_deux_ibans_meme_prompt(self):
        text = "compte FR7610107001011234567890129 et DE89370400440532013000"
        found = self._find(text)
        assert len(found) == 2

    def test_pas_iban(self):
        found = self._find("NOTANIBAN123456789")
        assert len(found) == 0

    def test_texte_innocent(self):
        found = self._find("bonjour je voudrais de l aide pour rediger un email")
        assert len(found) == 0


class TestCard:
    def _find(self, text):
        return [f for f in scan(text) if f.entity_type == EntityType.CARD]

    def test_visa_valide(self):
        found = self._find("carte 4532015112830366")
        assert len(found) == 1

    def test_visa_invalide_luhn(self):
        found = self._find("carte 4532015112830367")
        assert len(found) == 0

    def test_mastercard_valide(self):
        found = self._find("5425233430109903")
        assert len(found) == 1

    def test_amex_valide(self):
        found = self._find("379354508162306")
        assert len(found) == 1

    def test_pas_de_doublon_avec_iban(self):
        text = "FR7610107001011234567890129"
        iban = [f for f in scan(text) if f.entity_type == EntityType.IBAN]
        card = [f for f in scan(text) if f.entity_type == EntityType.CARD]
        assert len(iban) == 1
        assert len(card) == 0


class TestSecret:
    def _find(self, text):
        return [f for f in scan(text) if f.entity_type == EntityType.SECRET]

    def test_cle_openai(self):
        found = self._find("sk-abc123def456ghi789jkl012mno345pqrs")
        assert len(found) == 1

    def test_cle_groq(self):
        found = self._find("gsk_abc123def456ghi789jkl012mno345pqrst")
        assert len(found) == 1

    def test_cle_aws(self):
        found = self._find("AKIAIOSFODNN7EXAMPLE")
        assert len(found) == 1

    def test_token_github(self):
        # ghp_ suivi de 36 caracteres alphanumeriques (format reel GitHub PAT)
        found = self._find("ghp_1234567890abcdefghijklmnopqrstuvwxyz")
        assert len(found) == 1

    def test_token_slack(self):
        found = self._find("xoxb-abc123-def456-ghi789jkl012")
        assert len(found) == 1

    def test_texte_innocent(self):
        found = self._find("bonjour, comment puis-je vous aider ?")
        assert len(found) == 0

    def test_sk_court_rejete(self):
        found = self._find("sk-abc")
        assert len(found) == 0