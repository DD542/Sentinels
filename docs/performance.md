# Performance mesurée

> Chiffres reproductibles avec `python backend/tests/loadtest.py`.
> Machine de mesure : poste de développement Windows, **un seul
> processus**, Python 3.14, sans appel aux fournisseurs d'IA (leur
> latence n'est pas la nôtre). Ce sont des ordres de grandeur honnêtes,
> pas des chiffres de plaquette : mesurez sur votre matériel.

## Capacité d'un processus

Endpoint `/gateway/scan`, mélange réaliste de prompts (la majorité sans
donnée sensible), latence HTTP de bout en bout.

| Requêtes simultanées | p50 | p95 | Débit |
|---:|---:|---:|---:|
| 1 | 13 ms | 14 ms | 71 req/s |
| 4 | 48 ms | 57 ms | 68 req/s |
| 8 | 98 ms | 168 ms | 66 req/s |
| 16 | 190 ms | 530 ms | 58 req/s |

Lecture : le temps de traitement d'un prompt est de **13 ms**. Le débit
plafonne autour de **65-70 requêtes par seconde par processus** — la
détection est un travail CPU (spaCy, Presidio) et Python n'exécute qu'un
fil à la fois. Au-delà, la latence croît par mise en file, ce qui est le
comportement attendu et prévisible.

Pour une entreprise de 200 personnes générant 4 000 prompts par jour,
**un seul processus suffit très largement** : la contrainte n'est pas le
volume mais la latence en pointe. Pour absorber des pics, ajoutez des
répliques (le chart Helm en déploie deux par défaut).

## Le journal d'audit ne ralentit plus rien

C'était le défaut fatal : la vérification d'intégrité relisait tout le
journal **à chaque requête**.

| État du journal | p50 | p95 | Débit |
|:---|---:|---:|---:|
| Vide (130 entrées) | 48 ms | 57 ms | 68 req/s |
| **50 130 entrées** | 51 ms | 63 ms | 65 req/s |

La latence est **invariante à la taille de l'historique**. Avant
correction, 50 000 entrées ajoutaient **2,5 secondes** à chaque requête,
et 100 000 en ajoutaient cinq — le produit devenait inutilisable en une
dizaine de jours d'usage réel.

Coût de l'état d'intégrité rapporté par les réponses d'API, mesuré
isolément : **1,2 µs** à 100 000 entrées, contre 5 064 ms auparavant.

## Le piège de la concurrence, et sa correction

La détection tourne dans des fils d'exécution. Sans borne, leur nombre
suit celui des requêtes — or il s'agit de travail **CPU** : au-delà du
nombre de cœurs, les fils se disputent le GIL et le débit **s'effondre**
au lieu de plafonner.

| À 16 requêtes simultanées | p50 | Débit |
|:---|---:|---:|
| Pool non borné | 1 000 ms | 12 req/s |
| **Pool borné au nombre de cœurs** | **190 ms** | **58 req/s** |

Le pool est désormais borné au démarrage (`DETECTION_WORKERS`, 0 = nombre
de cœurs). Le système met en file au lieu de s'écrouler : la dégradation
devient linéaire et prévisible.

## Reproduire les mesures

```bash
cd backend

# Capacité à concurrence donnée
python tests/loadtest.py --requests 150 --concurrency 8 --stages 1

# Invariance au volume : journal pré-rempli avant la mesure
python tests/loadtest.py --requests 200 --concurrency 4 --prefill 50000

# Avec Postgres (ajoute la latence réseau de la base)
python tests/loadtest.py --db --requests 500 --concurrency 8

# Sortie machine
python tests/loadtest.py --json
```

## Ce qui n'est pas mesuré ici

En toute transparence :

- **Le mode Postgres distant.** Avec une base gérée hors du réseau local
  (Neon depuis un poste : ~150 ms d'aller-retour), chaque scan effectue
  plusieurs écritures et la latence est dominée par le réseau, pas par
  SENTINEL. En production, placez la base dans la même région que la
  passerelle.
- **Les appels fournisseurs.** `/gateway/chat` ajoute la latence du
  modèle (souvent plusieurs secondes) : elle n'est pas imputable à la
  passerelle, et le streaming natif la masque en grande partie.
- **La montée en charge multi-répliques.** SENTINEL est sans état hors
  base : plusieurs répliques fonctionnent, mais l'accélération réelle
  reste à mesurer.
- **Le poste de mesure n'est pas un serveur.** Attendez-vous à mieux sur
  une machine dédiée, à moins bon sur un conteneur bridé à 250 mCPU
  (les requêtes du chart Helm sont volontairement basses).
