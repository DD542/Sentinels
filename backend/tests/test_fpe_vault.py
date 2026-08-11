from __future__ import annotations
import re
import pytest
from app.detection.types import EntityType
from app.vault.fpe import tokenize, detokenize


_SEP = re.compile(r"[\s\u00A0-]")


def _mod97(iban: str) -> int:
    norm = _SEP.sub("", iban).upper()
    rearranged = norm[4:] + norm[:4]
    numeric = "".join(str(int(c, 36)) for c in rearranged)
    return int(numeric) % 97


class TestFPEIBAN:
    def test_token_iban_valide_mod97(self):
        real = "FR7610107001011234567890129"
        token = tokenize(real, EntityType.IBAN)
        assert _mod97(token) == 1, f"IBAN factice invalide: {token}"

    def test_token_iban_meme_pays(self):
        real = "DE89370400440532013000"
        token = tokenize(real, EntityType.IBAN)
        assert _SEP.sub("", token).startswith("DE")

    def test_token_iban_different_du_vrai(self):
        real = "FR7610107001011234567890129"
        token = tokenize(real, EntityType.IBAN)
        assert _SEP.sub("", token) != _SEP.sub("", real)

    def test_token_deterministe(self):
        real = "FR7610107001011234567890129"
        assert tokenize(real, EntityType.IBAN) == tokenize(real, EntityType.IBAN)

    def test_detokenize_exact(self):
        real = "FR7610107001011234567890129"
        token = tokenize(real, EntityType.IBAN)
        assert real in detokenize(f"virement vers {token}")

    def test_detokenize_tolerant_espaces(self):
        real = "FR7610107001011234567890129"
        token = tokenize(real, EntityType.IBAN)
        spaced = " ".join(token)
        assert real in detokenize(spaced)

    def test_detokenize_fuzzy_iban_corrompu(self):
        """Régression : LLM qui corrompt des chiffres -> récupération floue."""
        real = "FR7610107001011234567890129"
        token = tokenize(real, EntityType.IBAN)
        corrupted = token[:4] + str((int(token[4]) + 1) % 10) + token[5:]
        assert real in detokenize(f"votre IBAN est {corrupted}")


class TestFPEPerson:
    def test_masculin_remplace_par_masculin(self):
        """Régression : Jean ne doit pas devenir Anne."""
        token = tokenize("Jean Dupont", EntityType.PERSON)
        from app.vault.fpe import _FAKE_MALE as masculine
        assert token.split()[0] in masculine, f"Prénom masculin attendu: {token}"

    def test_feminin_remplace_par_feminin(self):
        token = tokenize("Marie Martin", EntityType.PERSON)
        from app.vault.fpe import _FAKE_FEMALE as feminine
        assert token.split()[0] in feminine, f"Prénom féminin attendu: {token}"

    def test_token_person_deterministe(self):
        assert tokenize("Jean Dupont", EntityType.PERSON) == tokenize("Jean Dupont", EntityType.PERSON)

    def test_deux_personnes_differentes(self):
        assert tokenize("Jean Dupont", EntityType.PERSON) != tokenize("Pierre Martin", EntityType.PERSON)

    def test_detokenize_person(self):
        real = "Jean Dupont"
        token = tokenize(real, EntityType.PERSON)
        assert real in detokenize(f"bonjour {token}")


class TestFPEEmail:
    def test_token_email_format(self):
        token = tokenize("jean.dupont@societe.fr", EntityType.EMAIL)
        assert "@exemple.fr" in token

    def test_token_email_different(self):
        token = tokenize("jean.dupont@societe.fr", EntityType.EMAIL)
        assert token != "jean.dupont@societe.fr"


class TestFPEDigits:
    def test_siret_longueur_preservee(self):
        real = "12345678901234"
        token = tokenize(real, EntityType.SIRET)
        assert len(token.replace(" ", "")) == len(real)

    def test_phone_format_preserve(self):
        real = "06 12 34 56 78"
        token = tokenize(real, EntityType.PHONE_FR)
        assert len(token) == len(real)
