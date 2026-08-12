"""
Cloisonnement CRYPTOGRAPHIQUE du vault.

Le vault etait cloisonne par une clause SQL. Or c'est exactement une
erreur de cloisonnement logique qui avait deja livre a un client les
donnees d'un autre : la requete rendait des lignes, et ces lignes se
lisaient.

Avec une cle par client, la meme erreur ne rend plus rien — la ligne
revient, mais elle ne se dechiffre pas. Ces tests simulent donc le pire
cas : une requete DEFAILLANTE qui renvoie les lignes de tout le monde.
"""
from __future__ import annotations
import pytest

from app import db
from app.config import get_settings

settings = get_settings()
IBAN = "FR7610107001011234567890129"
CLE_A = "a1" * 32
CLE_B = "b2" * 32


@pytest.fixture(autouse=True)
def cles_propres(monkeypatch):
    monkeypatch.setattr(settings, "vault_master_key", "c3" * 32)
    monkeypatch.setattr(settings, "vault_client_keys", "")
    db._reset_key_cache()
    yield
    db._reset_key_cache()


class TestClesDerivees:
    def test_chaque_client_a_sa_cle(self):
        assert (db.encrypt(IBAN, "a") != db.encrypt(IBAN, "b"))

    def test_un_client_ne_lit_pas_le_chiffre_d_un_autre(self):
        """LE test : meme en RECEVANT la ligne, B n'en tire rien."""
        chiffre_pour_a = db.encrypt(IBAN, "client-a")
        assert db.decrypt(chiffre_pour_a, "client-b") is None
        assert db.decrypt(chiffre_pour_a, "client-a") == IBAN

    def test_deterministe_entre_processus(self):
        """La cle doit se rederiver a l'identique : sinon un redemarrage
        ou un second worker rendrait le vault illisible."""
        chiffre = db.encrypt(IBAN, "client-a")
        db._reset_key_cache()
        assert db.decrypt(chiffre, "client-a") == IBAN

    def test_changement_de_cle_maitre_rend_illisible(self, monkeypatch):
        chiffre = db.encrypt(IBAN, "client-a")
        monkeypatch.setattr(settings, "vault_master_key", "d4" * 32)
        db._reset_key_cache()
        assert db.decrypt(chiffre, "client-a") is None


class TestCompatibiliteAscendante:
    def test_lignes_anterieures_relues(self):
        """Les lignes ecrites avant le cloisonnement doivent rester
        lisibles, sinon la mise a jour ferait perdre le vault en cours."""
        ancien = db._fernet().encrypt(IBAN.encode()).decode()
        assert db.decrypt(ancien, "client-a") == IBAN

    def test_le_repli_ne_traverse_pas_les_clients(self):
        """Le repli relit l'ANCIEN format, il ne rouvre pas un passage
        entre clients : une ligne au nouveau format reste cloisonnee."""
        nouveau = db.encrypt(IBAN, "client-a")
        assert db.decrypt(nouveau, "client-b") is None


class TestClesFourniesParLeClient:
    @pytest.fixture(autouse=True)
    def byok(self, monkeypatch):
        monkeypatch.setattr(settings, "vault_client_keys",
                            '{"client-a": "%s"}' % CLE_A)
        db._reset_key_cache()

    def test_l_exploitant_ne_peut_pas_dechiffrer(self, monkeypatch):
        """La promesse vendue au service achats : la cle maitre de
        SENTINEL ne suffit PAS a lire le vault de ce client."""
        chiffre = db.encrypt(IBAN, "client-a")
        monkeypatch.setattr(settings, "vault_client_keys", "")
        db._reset_key_cache()
        assert db.decrypt(chiffre, "client-a") is None

    def test_aucun_repli_pour_un_client_a_cle_propre(self):
        """Le repli historique redonnerait a l'exploitant la capacite de
        lire : il doit etre coupe des qu'un client fournit sa cle."""
        ancien = db._fernet().encrypt(IBAN.encode()).decode()
        assert db.decrypt(ancien, "client-a") is None

    def test_les_autres_clients_restent_sur_la_cle_derivee(self):
        chiffre = db.encrypt(IBAN, "client-b")
        assert db.decrypt(chiffre, "client-b") == IBAN
        assert db.decrypt(chiffre, "client-a") is None

    def test_cle_differente_du_maitre(self, monkeypatch):
        """La cle du client ne doit rien devoir a la notre."""
        chiffre = db.encrypt(IBAN, "client-a")
        monkeypatch.setattr(settings, "vault_client_keys",
                            '{"client-a": "%s"}' % CLE_B)
        db._reset_key_cache()
        assert db.decrypt(chiffre, "client-a") is None


class TestValidationDeLaConfiguration:
    def test_json_invalide_refuse(self, monkeypatch):
        monkeypatch.setattr(settings, "vault_client_keys", "{pas du json")
        with pytest.raises(ValueError, match="JSON"):
            settings.client_vault_keys

    def test_cle_trop_courte_refusee(self, monkeypatch):
        """Accepter une cle mal formee en l'ignorant ferait retomber le
        client sur la cle derivee : il croirait detenir la seule copie."""
        monkeypatch.setattr(settings, "vault_client_keys", '{"a": "abcd"}')
        with pytest.raises(ValueError, match="hexadecimaux"):
            settings.client_vault_keys

    def test_cle_non_hexadecimale_refusee(self, monkeypatch):
        monkeypatch.setattr(settings, "vault_client_keys",
                            '{"a": "%s"}' % ("z" * 64))
        with pytest.raises(ValueError, match="hexadecimal"):
            settings.client_vault_keys

    def test_objet_attendu(self, monkeypatch):
        monkeypatch.setattr(settings, "vault_client_keys", '["a"]')
        with pytest.raises(ValueError, match="objet"):
            settings.client_vault_keys


class TestBoutEnBout:
    @pytest.mark.asyncio
    async def test_une_requete_sans_filtre_ne_fuit_rien(self, monkeypatch):
        """Simulation du pire cas : la base renvoie a B les lignes de A.

        C'est precisement le scenario du defaut corrige precedemment. Le
        cloisonnement cryptographique doit le rendre inoffensif."""
        from app.detection.types import EntityType
        from app.vault import fpe

        lignes: list[dict] = []

        class _Con:
            async def execute(self, sql, *args):
                if sql.startswith("INSERT INTO vault"):
                    lignes.append({"token": args[1], "cipher": args[2],
                                   "entity_type": args[3]})

            async def fetch(self, sql, *args):
                return list(lignes)          # AUCUN filtre : la faute

        class _Pool:
            def acquire(self):
                class _Ctx:
                    async def __aenter__(s): return _Con()
                    async def __aexit__(s, *a): return False
                return _Ctx()

        monkeypatch.setattr(db, "is_enabled", lambda: True)
        monkeypatch.setattr(db, "pool", lambda: _Pool())
        fpe._REVERSE_MAP.clear()
        fpe._EXPIRATIONS.clear()

        jeton = await fpe.tokenize_async(IBAN, EntityType.IBAN,
                                         client_id="client-a")
        fpe._REVERSE_MAP.clear()             # force la relecture en base
        fpe._EXPIRATIONS.clear()

        restaure = await fpe.detokenize_async(f"vers {jeton}", "client-b")
        assert IBAN not in restaure
        assert await fpe.detokenize_async(f"vers {jeton}", "client-a") \
            == f"vers {IBAN}"
