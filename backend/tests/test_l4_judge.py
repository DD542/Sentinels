"""
Tests du juge local (L4) — rattrapage de rappel sur le texte libre.

Le modele n'est pas appele ici : on simule ses reponses. Ce qui est
teste, c'est le CONTRAT autour de lui — car un juge probabiliste dans un
outil de securite doit etre encadre :

  * une entite hallucinee (absente du texte) est rejetee ;
  * sa confiance ne depasse jamais celle d'une validation deterministe ;
  * son indisponibilite ne fait jamais echouer une analyse ;
  * il ne se declenche pas sans que le client l'ait demande — une
    inference coute mille fois le reste du pipeline.
"""
from __future__ import annotations
import pytest

from app import policy
from app.detection import l4_judge
from app.detection.engine import DetectionEngine
from app.detection.types import EntityType


@pytest.fixture(autouse=True)
def reset_policies():
    policy._reset()
    yield
    policy._reset()


def _reponse(entites):
    """Simule la reponse d'Ollama."""
    class _Resp:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            import json as _j
            return {"message": {"content": _j.dumps({"entities": entites})}}

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, *a, **k):
            return _Resp()

    return _Client


class TestExtraction:
    async def test_entite_positionnee(self, monkeypatch):
        texte = "Le dossier de Jean Dupont est pret."
        monkeypatch.setattr(l4_judge.httpx, "AsyncClient",
                            lambda **k: _reponse([{"type": "PERSON",
                                                   "text": "Jean Dupont"}])())
        trouves = await l4_judge.judge(texte)
        assert len(trouves) == 1
        f = trouves[0]
        assert f.entity_type == EntityType.PERSON
        assert texte[f.start:f.end] == "Jean Dupont"
        assert f.layer == "L4"

    async def test_hallucination_rejetee(self, monkeypatch):
        """Le modele propose un nom absent du texte : on refuse."""
        monkeypatch.setattr(l4_judge.httpx, "AsyncClient",
                            lambda **k: _reponse([{"type": "PERSON",
                                                   "text": "Marie Curie"}])())
        assert await l4_judge.judge("Un texte sans aucun nom.") == []

    async def test_occurrences_multiples(self, monkeypatch):
        texte = "Dupont a vu Dupont hier."
        monkeypatch.setattr(l4_judge.httpx, "AsyncClient",
                            lambda **k: _reponse([{"type": "PERSON",
                                                   "text": "Dupont"}])())
        trouves = await l4_judge.judge(texte)
        assert len(trouves) == 2
        assert [f.start for f in trouves] == [0, 12]

    async def test_confiance_plafonnee(self, monkeypatch):
        """Un juge probabiliste ne bat jamais une somme de controle."""
        monkeypatch.setattr(l4_judge.httpx, "AsyncClient",
                            lambda **k: _reponse([{"type": "PERSON",
                                                   "text": "Dupont"}])())
        f = (await l4_judge.judge("Dupont"))[0]
        assert f.confidence <= 0.8

    async def test_types_inconnus_ignores(self, monkeypatch):
        monkeypatch.setattr(l4_judge.httpx, "AsyncClient",
                            lambda **k: _reponse([
                                {"type": "ORG", "text": "Acme"},
                                {"type": "PERSON", "text": "Acme"}])())
        trouves = await l4_judge.judge("Acme")
        assert [f.entity_type for f in trouves] == [EntityType.PERSON]


class TestDegradation:
    async def test_ollama_injoignable(self, monkeypatch):
        class _Casse:
            async def __aenter__(self):
                raise ConnectionError("injoignable")

            async def __aexit__(self, *exc):
                return False

        monkeypatch.setattr(l4_judge.httpx, "AsyncClient", lambda **k: _Casse())
        assert await l4_judge.judge("Jean Dupont") == []

    async def test_json_invalide(self, monkeypatch):
        class _Resp:
            def raise_for_status(self): pass
            def json(self): return {"message": {"content": "pas du json"}}

        class _Client:
            async def __aenter__(self): return self
            async def __aexit__(self, *e): return False
            async def post(self, *a, **k): return _Resp()

        monkeypatch.setattr(l4_judge.httpx, "AsyncClient", lambda **k: _Client())
        assert await l4_judge.judge("Jean Dupont") == []

    async def test_reponse_sans_entites(self, monkeypatch):
        monkeypatch.setattr(l4_judge.httpx, "AsyncClient",
                            lambda **k: _reponse([])())
        assert await l4_judge.judge("Bonjour") == []


class TestDeclenchement:
    async def test_desactive_par_defaut(self):
        """Sans demande explicite, aucune inference : la latence du
        pipeline reste de l'ordre de la milliseconde."""
        assert policy.deep_scan_enabled("un-client") is False

    async def test_active_par_politique(self):
        await policy.set_policy("acme", {"deep_scan": True})
        assert policy.deep_scan_enabled("acme") is True
        assert policy.deep_scan_enabled("autre") is False

    async def test_pas_d_appel_sans_deep_scan(self, monkeypatch):
        appels = {"n": 0}

        async def _compter(text):
            appels["n"] += 1
            return []

        monkeypatch.setattr(l4_judge, "judge", _compter)
        moteur = DetectionEngine()
        # Texte franchement detecte : ni ambigu, ni deep_scan.
        await moteur.analyze("virement vers FR7610107001011234567890129",
                             "sans-deep")
        assert appels["n"] == 0

    async def test_appel_unique_avec_deep_scan(self, monkeypatch):
        """Une seule inference, malgre les vues de-obfusquees : le juge
        lit le sens, pas l'encodage."""
        appels = {"n": 0}

        async def _compter(text):
            appels["n"] += 1
            return []

        monkeypatch.setattr(l4_judge, "judge", _compter)
        await policy.set_policy("acme", {"deep_scan": True})
        moteur = DetectionEngine()
        import base64
        cache = base64.b64encode(b"FR7610107001011234567890129").decode()
        await moteur.analyze(f"donnee {cache} et Jean Dupont", "acme")
        assert appels["n"] == 1

    async def test_pas_de_doublon_avec_les_couches_deterministes(self, monkeypatch):
        """Si L1 a deja vu l'entite, L4 ne la reajoute pas."""
        async def _juge(text):
            from app.detection.types import Finding
            i = text.index("FR76")
            return [Finding(entity_type=EntityType.IBAN, start=i,
                            end=i + 27, value=text[i:i + 27],
                            confidence=0.7, layer="L4")]

        monkeypatch.setattr(l4_judge, "judge", _juge)
        await policy.set_policy("acme", {"deep_scan": True})
        moteur = DetectionEngine()
        res = await moteur.analyze("virement FR7610107001011234567890129", "acme")
        assert sum(1 for f in res.findings
                   if f.entity_type == EntityType.IBAN) == 1


class TestPolitique:
    async def test_deep_scan_dans_la_politique(self):
        applique = await policy.set_policy("acme", {"deep_scan": True})
        assert applique["deep_scan"] is True

    def test_valeur_non_booleenne_refusee(self):
        with pytest.raises(ValueError, match="booleen"):
            policy.validate({"deep_scan": "oui"})
