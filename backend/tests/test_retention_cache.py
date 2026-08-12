"""
La duree de conservation s'applique AUSSI au cache memoire.

Defaut corrige : `_REVERSE_MAP` n'avait aucune echeance. Deux
consequences mesurees :

  1. **Une promesse ecrite non tenue.** `docs/politique-retention.md`
     annonce la suppression des jetons apres VAULT_TTL_HOURS. La base
     l'appliquait ; la memoire, non. Un processus demarre depuis trente
     jours restaurait encore les jetons du premier jour.
  2. **Une fuite de memoire.** Mesure : 20 000 jetons -> 2,7 Mo, et
     `purge_expired()` n'en evinçait aucun. Au debit mesure (~70 req/s),
     environ 1,7 Go par jour et par processus.
"""
from __future__ import annotations
import time

import pytest

from app.config import get_settings
from app.detection.types import EntityType
from app.vault import fpe

settings = get_settings()
IBAN = "FR7610107001011234567890129"


@pytest.fixture(autouse=True)
def vault_propre():
    fpe._REVERSE_MAP.clear()
    fpe._EXPIRATIONS.clear()
    yield
    fpe._REVERSE_MAP.clear()
    fpe._EXPIRATIONS.clear()


def _perimer(client_id: str, token: str) -> None:
    """Fait passer l'echeance d'un jeton dans le passe."""
    fpe._client_expirations(client_id)[token] = time.time() - 1


class TestEcheances:
    def test_tokenize_pose_une_echeance(self):
        token = fpe.tokenize(IBAN, EntityType.IBAN, client_id="a")
        echeance = fpe._client_expirations("a")[token]
        attendu = time.time() + settings.vault_ttl_hours * 3600
        assert abs(echeance - attendu) < 5

    @pytest.mark.asyncio
    async def test_tokenize_async_pose_une_echeance(self):
        token = await fpe.tokenize_async(IBAN, EntityType.IBAN, client_id="a")
        assert token in fpe._client_expirations("a")

    def test_entree_posee_a_la_main_reste_valide(self):
        """Outils et tests remplissent parfois le vault directement :
        l'absence d'echeance ne doit pas les faire disparaitre."""
        fpe._client_map("a")["Hugo Blanc"] = ("Jean Dupont", EntityType.PERSON)
        assert fpe.detokenize("Bonjour Hugo Blanc", "a") == "Bonjour Jean Dupont"


class TestJetonPerime:
    def test_un_jeton_perime_ne_restaure_plus_rien(self):
        """Le coeur de la promesse : passe l'echeance, la correspondance
        n'existe plus — meme si la passe de maintenance n'est pas encore
        passee."""
        token = fpe.tokenize(IBAN, EntityType.IBAN, client_id="a")
        assert IBAN in fpe.detokenize(f"vers {token}", "a")

        _perimer("a", token)
        assert IBAN not in fpe.detokenize(f"vers {token}", "a")

    @pytest.mark.asyncio
    async def test_perime_ignore_en_asynchrone(self):
        token = await fpe.tokenize_async(IBAN, EntityType.IBAN, client_id="a")
        _perimer("a", token)
        assert IBAN not in await fpe.detokenize_async(f"vers {token}", "a")

    @pytest.mark.asyncio
    async def test_perime_ignore_en_streaming(self):
        token = await fpe.tokenize_async(IBAN, EntityType.IBAN, client_id="a")
        _perimer("a", token)
        d = await fpe.make_incremental_detokenizer("a")
        assert IBAN not in d.feed(f"vers {token}") + d.flush()

    def test_un_jeton_valide_survit_a_la_peremption_d_un_autre(self):
        vieux = fpe.tokenize(IBAN, EntityType.IBAN, client_id="a")
        neuf = fpe.tokenize("Jean Dupont", EntityType.PERSON, client_id="a")
        _perimer("a", vieux)
        sortie = fpe.detokenize(f"{vieux} et {neuf}", "a")
        assert IBAN not in sortie
        assert "Jean Dupont" in sortie


class TestEviction:
    @pytest.mark.asyncio
    async def test_purge_libere_reellement_la_memoire(self):
        """Le test qui manquait : avant, `purge_expired()` laissait le
        cache intact (19 999 -> 19 999 jetons)."""
        for i in range(200):
            fpe.tokenize(f"Personne Numero{i}", EntityType.PERSON, client_id="a")
        assert len(fpe._client_map("a")) == 200

        for token in list(fpe._client_map("a")):
            _perimer("a", token)
        await fpe.purge_expired()
        assert len(fpe._client_map("a")) == 0
        assert len(fpe._client_expirations("a")) == 0

    @pytest.mark.asyncio
    async def test_purge_epargne_les_jetons_valides(self):
        vieux = fpe.tokenize(IBAN, EntityType.IBAN, client_id="a")
        neuf = fpe.tokenize("Jean Dupont", EntityType.PERSON, client_id="a")
        _perimer("a", vieux)
        await fpe.purge_expired()
        assert vieux not in fpe._client_map("a")
        assert neuf in fpe._client_map("a")

    @pytest.mark.asyncio
    async def test_purge_traverse_tous_les_clients(self):
        """Un client silencieux ne doit pas garder sa memoire ad vitam
        parce qu'un autre est actif."""
        for client in ("a", "b", "c"):
            token = fpe.tokenize(IBAN, EntityType.IBAN, client_id=client)
            _perimer(client, token)
        await fpe.purge_expired()
        assert all(not fpe._client_map(c) for c in ("a", "b", "c"))

    @pytest.mark.asyncio
    async def test_purge_sans_base_evince_quand_meme(self):
        """Le deploiement sans Postgres n'echappe pas a la retention :
        avant, `purge_expired()` renvoyait 0 immediatement."""
        token = fpe.tokenize(IBAN, EntityType.IBAN, client_id="a")
        _perimer("a", token)
        assert await fpe.purge_expired() == 0     # aucune ligne en base
        assert fpe._client_map("a") == {}          # cache tout de meme vide


class TestRapportDeMaintenance:
    @pytest.mark.asyncio
    async def test_eviction_rapportee_separement(self):
        """L'exploitant doit distinguer les deux : la base est partagee,
        le cache est local a chaque processus."""
        from app import maintenance
        token = fpe.tokenize(IBAN, EntityType.IBAN, client_id="a")
        _perimer("a", token)
        rapport = await maintenance.run_once()
        assert rapport["vault_cache_evicted"] == 1
        assert rapport["vault_tokens_deleted"] == 0     # pas de base ici


class TestCloisonnementPreserve:
    def test_la_peremption_n_ouvre_pas_de_passage_entre_clients(self):
        """Regression : l'ajout des echeances ne doit pas reintroduire le
        vault partage corrige precedemment."""
        token = fpe.tokenize(IBAN, EntityType.IBAN, client_id="a")
        assert IBAN not in fpe.detokenize(f"vers {token}", "b")
