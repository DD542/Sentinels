"""
Cloisonnement du vault et unicite des jetons.

Ces tests reproduisent deux defauts reels, trouves par preuve de concept
et corriges. Ils existent pour qu'ils ne reviennent jamais.

DEFAUT 1 — fuite inter-clients. La table `vault` n'avait aucune colonne
client, la relecture aucun filtre, et le cache memoire etait un
dictionnaire global. La reponse d'un fournisseur destinee au client B,
contenant par hasard un jeton du client A, se voyait restaurer avec la
VRAIE valeur de A. Dans un outil de protection des donnees, c'est le
pire defaut possible.

DEFAUT 2 — collisions de jetons. L'espace des substituts faisait 98
combinaisons (7x7 prenoms, 7 noms) et 5 villes. Mesure : 3 collisions
sur 20 personnes. Une collision corrompt DEUX valeurs — le vault ne
retient que la derniere — et fait fuiter l'une chez l'autre.
"""
from __future__ import annotations
import pytest

from app.vault import fpe
from app.detection.types import EntityType

IBAN_A = "FR7610107001011234567890129"
IBAN_B = "FR7630001007941234567890185"


class TestCloisonnement:
    async def test_un_client_ne_restaure_pas_les_donnees_d_un_autre(self):
        """LE test. Il reproduit la fuite exacte."""
        jeton = await fpe.tokenize_async("Jean Dupont", EntityType.PERSON, "A")
        reponse = f"Votre interlocuteur est {jeton}."

        recu_par_b = await fpe.detokenize_async(reponse, "B")
        assert "Jean Dupont" not in recu_par_b
        assert jeton in recu_par_b          # B garde le substitut, inoffensif

        recu_par_a = await fpe.detokenize_async(reponse, "A")
        assert "Jean Dupont" in recu_par_a  # A retrouve bien sa donnee

    async def test_iban_non_restaure_chez_un_autre(self):
        jeton = await fpe.tokenize_async(IBAN_A, EntityType.IBAN, "A")
        recu = await fpe.detokenize_async(f"Compte : {jeton}", "B")
        assert IBAN_A not in recu

    async def test_vaults_independants(self):
        await fpe.tokenize_async(IBAN_A, EntityType.IBAN, "A")
        await fpe.tokenize_async(IBAN_B, EntityType.IBAN, "B")
        assert set(fpe._client_map("A")) != set(fpe._client_map("B"))
        assert len(fpe._client_map("A")) == 1
        assert len(fpe._client_map("B")) == 1

    async def test_meme_valeur_chez_deux_clients(self):
        """Deux clients qui traitent la meme personne : chacun restaure
        la sienne, sans interference."""
        ja = await fpe.tokenize_async("Marie Curie", EntityType.PERSON, "A")
        jb = await fpe.tokenize_async("Marie Curie", EntityType.PERSON, "B")
        assert "Marie Curie" in await fpe.detokenize_async(f"vu {ja}", "A")
        assert "Marie Curie" in await fpe.detokenize_async(f"vu {jb}", "B")

    async def test_flux_incremental_cloisonne(self):
        """Le streaming natif doit respecter le meme cloisonnement."""
        jeton = await fpe.tokenize_async("Jean Dupont", EntityType.PERSON, "A")
        detok = await fpe.make_incremental_detokenizer("B")
        sortie = detok.feed(f"Bonjour {jeton}, ") + detok.flush()
        assert "Jean Dupont" not in sortie

    def test_version_synchrone_cloisonnee(self):
        jeton = fpe.tokenize("Jean Dupont", EntityType.PERSON, "A")
        assert "Jean Dupont" not in fpe.detokenize(f"vu {jeton}", "B")
        assert "Jean Dupont" in fpe.detokenize(f"vu {jeton}", "A")


class TestUniciteDesJetons:
    async def test_aucune_collision_sur_vingt_personnes(self):
        """Mesure avant correction : 3 collisions sur ces 20 noms."""
        noms = ["Jean Dupont", "Marie Martin", "Pierre Bernard", "Sophie Petit",
                "Luc Robert", "Anne Richard", "Paul Durand", "Claire Moreau",
                "Marc Simon", "Julie Laurent", "Louis Michel", "Nadia Garcia",
                "Denis David", "Lea Bertrand", "Victor Roux", "Manon Vincent",
                "Simon Fournier", "Alice Morel", "Hugo Girard", "Emma Andre"]
        jetons = [await fpe.tokenize_async(n, EntityType.PERSON, "acme")
                  for n in noms]
        assert len(set(jetons)) == len(noms)

    async def test_aucune_collision_a_l_echelle(self):
        """Mille personnes chez un meme client : toujours zero collision."""
        noms = [f"Prenom{i} Nom{i}" for i in range(1000)]
        jetons = [await fpe.tokenize_async(n, EntityType.PERSON, "grand")
                  for n in noms]
        assert len(set(jetons)) == 1000

    async def test_aucune_collision_sur_les_villes(self):
        """L'espace le plus contraint auparavant : 5 villes factices."""
        villes = ["Paris", "Lyon", "Marseille", "Toulouse", "Nice", "Nantes",
                  "Bordeaux", "Lille", "Rennes", "Reims", "Toulon", "Brest"]
        jetons = [await fpe.tokenize_async(v, EntityType.LOCATION, "acme")
                  for v in villes]
        assert len(set(jetons)) == len(villes)

    async def test_determinisme_conserve(self):
        """La resolution de collision ne doit pas casser la propriete
        essentielle : la meme valeur donne toujours le meme jeton."""
        for _ in range(5):
            assert (await fpe.tokenize_async("Jean Dupont",
                                             EntityType.PERSON, "acme")
                    == await fpe.tokenize_async("Jean Dupont",
                                                EntityType.PERSON, "acme"))

    async def test_espace_suffisant(self):
        """Le nombre de substituts doit rester tres superieur au nombre de
        personnes qu'un client tokenise reellement."""
        espace = (len(fpe._FAKE_MALE) + len(fpe._FAKE_FEMALE)) * len(fpe._FAKE_LAST)
        assert espace > 5000, f"espace insuffisant : {espace}"
        assert len(fpe._FAKE_CITIES) >= 30

    async def test_genre_conserve_malgre_la_redérivation(self):
        """Un prenom masculin reste masculin apres resolution de collision."""
        jeton = await fpe.tokenize_async("Jean Dupont", EntityType.PERSON, "x")
        assert jeton.split()[0] in fpe._FAKE_MALE
        jeton = await fpe.tokenize_async("Marie Martin", EntityType.PERSON, "x")
        assert jeton.split()[0] in fpe._FAKE_FEMALE

    async def test_iban_factice_reste_structurellement_valide(self):
        """La redérivation ne doit pas casser la cle mod-97."""
        from app.detection import l1_deterministic as l1
        jeton = await fpe.tokenize_async(IBAN_A, EntityType.IBAN, "acme")
        assert [f for f in l1.scan(f"iban {jeton}")
                if f.entity_type == EntityType.IBAN]
