# Politique de conservation des données — ce que SENTINEL stocke, et ce qu'il ne stocke jamais

> Document destiné au DPO, au RSSI et aux équipes d'audit. Il décrit
> **exactement** ce qui est écrit sur disque, sous quelle forme, pour
> combien de temps, et comment le faire disparaître. Chaque affirmation
> est vérifiable dans le code (fichiers cités) et couverte par des tests.

## Le principe

SENTINEL est un outil de protection des données : s'il stockait les
conversations de vos employés, il deviendrait lui-même le plus gros
risque de fuite de l'entreprise. Le choix d'architecture est donc
explicite et non négociable :

> **SENTINEL enregistre les *décisions*, jamais les *conversations*.**

## Ce que SENTINEL ne stocke JAMAIS

| Donnée | Pourquoi |
|:---|:---|
| **Le prompt brut de l'employé** | Aucune table ne contient le texte de la requête. Seuls sa longueur et les décisions prises sont journalisées. |
| **La réponse du fournisseur d'IA** | Elle transite en mémoire le temps de la désanonymisation, puis est renvoyée. Rien n'est écrit. |
| **Les clés API de vos fournisseurs** (OpenAI, Anthropic…) | Elles vivent dans la configuration serveur (`.env`), jamais en base. |
| **Vos clés client SENTINEL en clair** | Seule leur empreinte HMAC-SHA256 est stockée. Une clé perdue ne se récupère pas : elle se révoque et se recrée. |
| **Le contenu de vos documents confidentiels** | L'indexation L3 ne conserve que des empreintes non réversibles (shingles blake2b) et, en option, des vecteurs. |

## Ce que SENTINEL stocke (Postgres)

| Table | Contenu | Chiffrement | Conservation |
|:---|:---|:---|:---|
| `audit_chain` | Une ligne par décision : horodatage, action, type d'entité, hash chaîné. Le *détail* (dont la valeur détectée) est dans un champ chiffré. | **Fernet** (AES-128-CBC + HMAC), une clé de données distincte **par entité** | Les lignes sont conservées (la chaîne doit rester vérifiable) ; au-delà d'`AUDIT_RETENTION_DAYS` la **clé est détruite** et le détail devient illisible |
| `audit_keys` | La clé de chiffrement de chaque entité, elle-même **enveloppée** par une clé maître dérivée d'`AUDIT_HMAC_KEY` | Fernet (KEK à domaine séparé) | Tant que l'entité n'est pas oubliée |
| `vault` | La correspondance token factice → valeur réelle, nécessaire pour restaurer la vraie donnée dans la réponse | Fernet (clé dérivée de `VAULT_MASTER_KEY`) | **`VAULT_TTL_HOURS`, 24 h par défaut** — lignes supprimées par la purge périodique |
| `api_keys` | Empreinte HMAC de chaque clé client, statut actif/révoqué | Non réversible par construction | Permanente (révocation = passage à inactif) |
| `usage_counters` | Agrégats par client et par jour : nombre de prompts, tokenisations, blocages | Aucun (ce sont des compteurs, pas des données personnelles) | Permanente (facturation) |
| `provider_counters` | Nombre d'appels par fournisseur | Aucun | Permanente |
| `corpus_shingles` | Empreintes **non réversibles** (blake2b, 64 bits) des documents confidentiels, par client | Non réversible par construction — le texte n'est jamais stocké | Jusqu'à suppression du document (`DELETE /corpus/{doc_id}`) |
| `corpus_chunks` | Vecteurs sémantiques des documents (si embeddings activés) | Non réversible en pratique — le texte n'est jamais stocké | Idem |

**En mémoire uniquement** (perdu au redémarrage, par conception) : le flux
temps réel du dashboard (200 derniers événements).

## Les journaux applicatifs

Les logs sont structurés en JSON (une ligne par événement). Ils
contiennent le type d'entité, l'action, la couche de détection et le
hash d'audit — **jamais la valeur détectée**. Cette garantie est
verrouillée par un test automatisé qui échoue si une valeur sensible
apparaît dans une ligne de log (`backend/tests/test_logs.py`).

## Le droit à l'effacement (RGPD art. 17)

L'effacement se fait par **crypto-shredding**, en un appel :

```bash
curl -X POST http://<sentinel>/compliance/forget \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "<entité>", "admin_token": "<ADMIN_TOKEN>"}'
```

La clé de chiffrement de l'entité est détruite. Le détail de toutes ses
entrées d'audit devient **définitivement illisible**, y compris pour
l'exploitant, **sans réécrire ni casser le journal** : la chaîne de
hachage reste vérifiable.

C'est ce qui permet de tenir deux obligations contradictoires en
apparence : *prouver qu'un traitement a eu lieu* (AI Act art. 26(6)) tout
en *rendant la donnée personnelle irrécupérable* (RGPD art. 17). L'acte
d'effacement est lui-même scellé dans le journal, sous une entité
distincte, avec son horodatage et son hash.

## L'application des durées de conservation

Une durée annoncée mais jamais appliquée est une non-conformité
(RGPD art. 5(1)(e)). Une passe de purge tourne donc **périodiquement**
(`PURGE_INTERVAL_MINUTES`, 60 min par défaut, plus une passe au
démarrage) et reste déclenchable à la demande :

```bash
curl -X POST http://<sentinel>/admin/maintenance/purge   -H "X-Admin-Token: <ADMIN_TOKEN>"
```

Elle traite les deux stocks de façon **volontairement dissymétrique** :

| Stock | Traitement | Pourquoi |
|:---|:---|:---|
| **Vault** | Les jetons expirés sont **supprimés** | Ils n'ont qu'une utilité fonctionnelle (restaurer une valeur dans une réponse), aucune valeur probante |
| **Audit** | Les entrées sont **conservées**, leur **clé est détruite** | Supprimer une entrée casserait le chaînage de hachage et donc la preuve (AI Act art. 26(6)). En détruisant la clé, la preuve qu'un traitement a eu lieu demeure et la donnée personnelle devient illisible (RGPD art. 5(1)(e)) |

C'est le même mécanisme que l'effacement à la demande, appliqué
automatiquement par l'écoulement du temps : **on garde la preuve, on
perd la donnée.**

## Comment le vérifier vous-même

| Affirmation | Vérification |
|:---|:---|
| Le journal est inviolable | `GET /compliance/report` — champ « Vérification de la chaîne » ; toute altération casse le chaînage |
| Le rapport n'a pas été retouché | `GET /compliance/report.json` — signature HMAC recalculable avec votre clé d'audit |
| La donnée effacée l'est vraiment | Après `/compliance/forget`, le détail est illisible et l'intégrité reste vraie (`backend/tests/test_audit_crypto.py`) |
| Rien de sensible dans les logs | `backend/tests/test_logs.py` |
| La rétention du vault est appliquée | `backend/tests/test_vault_persistence.py` |
| Le corpus ne contient aucun texte | `backend/tests/test_corpus_persistence.py` |
| La rétention est réellement appliquée | `POST /admin/maintenance/purge` renvoie le décompte ; `backend/tests/test_maintenance.py` vérifie que l'intégrité survit à la purge |

## Limites, en toute transparence

- **La rétention de l'audit est illimitée par défaut** (`AUDIT_RETENTION_DAYS=0`) :
  c'est un choix explicite à poser avec votre DPO, pas un défaut que
  nous devrions décider à votre place.
- **L'effacement cible un identifiant technique d'entité** (`IBAN:12`),
  pas une personne. Répondre à une demande d'effacement portant sur un
  individu précis suppose de retrouver les entités concernées : une
  indexation par personne concernée n'est pas encore fournie.
- **Sans `DATABASE_URL`, rien n'est persisté** : mode démonstration, tout
  vit en mémoire. Utilisez `STRICT_MODE=true` en production pour refuser
  ce mode dégradé.
