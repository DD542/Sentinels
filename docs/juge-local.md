# Le juge local — rattrapage de rappel sur le texte libre

## Le problème qu'il résout

Sur les données **structurées** — IBAN, cartes, NIR, secrets — SENTINEL
est excellent, et c'est mathématique : une somme de contrôle ne se
trompe pas.

Sur le **texte libre**, c'est une autre histoire. Le benchmark externe
est sans appel : **34 % de F1 sur les noms de personnes**. Deux noms sur
trois passent. Ce n'est pas un défaut de réglage — c'est le plafond de
la reconnaissance d'entités française, et Presidio brut fait le même
score sur les mêmes lignes.

Or l'employé qui colle un compte rendu de réunion ou un courriel client
ne colle pas un IBAN isolé : il colle du texte plein de noms.

## Ce que le juge local change

Un modèle de langue comprend le contexte là où un modèle statistique
d'étiquetage plafonne. Mesuré sur 40 lignes du benchmark externe
(32 noms annotés), modèle `qwen2.5:14b` en local :

| | Précision | Rappel | F1 | Latence |
|:---|---:|---:|---:|---:|
| Couches L1–L3 seules | 48,1 % | 40,6 % | 44,1 % | 192 ms |
| **Avec le juge local** | **63,8 %** | **93,8 %** | **75,9 %** | 7 873 ms |

**Le rappel passe de 41 % à 94 %** : 17 noms rattrapés sur 32.

Le point contre-intuitif : **la précision augmente aussi** (48 % → 64 %).
Le juge ajoute bien quelques faux positifs (14 → 17), mais il apporte
surtout beaucoup de vrais positifs — le dénominateur bouge plus que le
numérateur.

> Ces chiffres portent sur un échantillon de 40 lignes, plus petit que
> les 300 lignes du benchmark principal, et sur les seuls noms de
> personnes. Ils indiquent un ordre de grandeur, pas une garantie.

## Ce qui a fait la différence : le prompt

L'ancienne version demandait un **verdict de sensibilité** — « ce texte
est-il sensible ? » — avec une consigne explicite : *« en cas de doute,
répondre non »*. La nouvelle demande une **extraction** : « liste les
données personnelles présentes ».

Sur les mêmes quatre textes de test : **3 noms trouvés sur 12** avec
l'ancien prompt, **12 sur 12** avec le nouveau. Et souvent plus vite,
l'ancien produisant de longues justifications inutiles.

La leçon est générale : *un juge prudent est excellent pour la précision
et catastrophique pour le rappel.* Si l'on veut du rappel, il faut
demander une extraction, pas un avis.

## Le prix, et pourquoi c'est désactivé par défaut

Une inférence coûte **5 à 25 secondes** contre 13 millisecondes pour le
reste du pipeline — un facteur mille. Le juge est donc **désactivé par
défaut** et s'active par client :

```bash
curl -X PUT http://<sentinel>/policy \
  -H "X-SENTINEL-Key: sntl_…" \
  -H "Content-Type: application/json" \
  -d '{"deep_scan": true}'
```

C'est un arbitrage explicite entre rappel et latence, à poser flux par
flux :

- **Activez-le** sur les traitements par lots, l'analyse de documents,
  les flux à fort enjeu (santé, RH, juridique) — là où quelques secondes
  ne coûtent rien et où un nom manqué coûte cher.
- **Laissez-le désactivé** sur la passerelle interactive, où l'employé
  attend sa réponse.

## Garde-fous

Un modèle probabiliste dans un outil de sécurité doit être encadré. Ces
règles sont testées :

| Garde-fou | Pourquoi |
|:---|:---|
| Toute entité **absente du texte est rejetée** | Le modèle peut halluciner un nom plausible ; on ne tokenise que ce qui existe vraiment, à sa position réelle |
| Confiance **plafonnée sous celle de L1** | Un juge probabiliste ne prime jamais sur une validation par somme de contrôle |
| **Aucun doublon** avec les couches déterministes | Une entité déjà vue par L1–L3 n'est pas réajoutée |
| **Une seule inférence** par analyse | Le juge lit le sens, pas l'encodage : l'appeler sur chaque variante dé-obfusquée multiplierait le coût pour un gain nul |
| **Dégradation propre** | Ollama absent, lent ou renvoyant du JSON invalide : liste vide, l'analyse continue. Une couche de rattrapage ne fait jamais échouer une détection |
| **Modèle local uniquement** | On ne vérifie pas la sensibilité d'une donnée en l'envoyant à un tiers |

La métrique `sentinel_l4_findings_total` compte les entités rattrapées :
c'est le chiffre qui justifie le coût.

## Mise en place

```env
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_JUDGE_MODEL=qwen2.5:14b
L4_TIMEOUT_SECONDS=30
```

En conteneur, `host.docker.internal` pointe vers l'hôte. Sans Ollama
joignable, la couche se désactive d'elle-même — aucune erreur, aucun
blocage.

## Limites connues

- **Mesure sur un échantillon réduit** (40 lignes). Refaites-la sur vos
  propres données avant d'en tirer un engagement contractuel.
- **Latence non bornée par le nombre de tokens** : un texte long coûte
  plus cher. La troncature à 4 000 caractères borne le pire cas.
- **Le modèle reste probabiliste.** Il rattrape beaucoup, il n'est pas
  exhaustif, et il produit encore des faux positifs — d'où la
  [liste d'exceptions par client](reglage-detection.md).
- **Un modèle plus petit dégrade le résultat.** Les chiffres ci-dessus
  sont ceux de `qwen2.5:14b` ; `qwen2.5:3b` est plus rapide mais moins
  fiable sur l'extraction exacte.
