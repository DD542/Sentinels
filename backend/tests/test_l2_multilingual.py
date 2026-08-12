from __future__ import annotations
import pytest

from app.detection import l2_ner
from app.detection.types import EntityType


class TestLanguageDetection:
    def test_francais(self):
        assert l2_ner.detect_language(
            "Rédige un email pour le client dans les délais") == "fr"

    def test_anglais(self):
        assert l2_ner.detect_language(
            "Write an email to the customer as soon as you can") == "en"

    def test_autre_langue(self):
        # Espagnol -> routé vers le modèle multilingue.
        assert l2_ner.detect_language(
            "Escribe un correo para el cliente de la empresa") == "other"

    def test_texte_vide(self):
        assert l2_ner.detect_language("") == "other"

    def test_chiffres_seuls(self):
        assert l2_ner.detect_language("12345 67890") == "other"


def _types(findings):
    return {f.entity_type for f in findings}


# La NER a besoin de l'extra `[detection]` (spaCy, Presidio, modèles).
# Sans lui ces tests seraient rouges pour une dépendance optionnelle
# absente — et un rouge permanent finit par être ignoré, ce qui masque
# les vrais. La CI, elle, installe l'extra : ils y sont bien exécutés.
besoin_ner = pytest.mark.skipif(
    not l2_ner.est_disponible(),
    reason='couche L2 absente — pip install -e ".[detection]"')


@besoin_ner
class TestMultilingualNER:
    def test_personne_et_lieu_anglais(self):
        f = l2_ner.scan_sync("Write an email to John Smith who lives in London")
        assert EntityType.PERSON in _types(f)
        assert any(x.value == "John Smith" for x in f)

    def test_personne_espagnol(self):
        f = l2_ner.scan_sync("Escribe un correo para Juan Garcia en Madrid")
        assert any(x.value == "Juan Garcia" for x in f)

    def test_personne_allemand(self):
        f = l2_ner.scan_sync("Schreibe eine E-Mail an Hans Mueller in Berlin")
        assert any("Hans" in x.value for x in f
                   if x.entity_type == EntityType.PERSON)

    def test_francais_toujours_ok(self):
        f = l2_ner.scan_sync("Rédige un email pour Jean Dupont à Paris")
        assert any(x.value == "Jean Dupont" for x in f)

    def test_metadonnee_langue_presente(self):
        f = l2_ner.scan_sync("Write to John Smith in London")
        assert all("lang" in x.meta for x in f)
