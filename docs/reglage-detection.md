# Régler la détection pour votre organisation

## Pourquoi ce réglage existe

Le faux positif coûte plus cher que le faux négatif.

Si SENTINEL tokenise « Martin » à chaque prompt parce que votre société
s'appelle *Martin & Associés*, la réponse du modèle devient absurde.
L'employé en conclut que l'outil casse son travail, et il le contourne —
il ira coller son texte dans ChatGPT depuis son navigateur personnel. Une
protection contournée ne protège rien.

Le réglage n'est donc pas un confort : c'est une condition d'adoption.

## Trois leviers

Chaque client règle **sa** détection ; les politiques sont cloisonnées,
comme les corpus.

```bash
curl -X PUT http://<sentinel>/policy \
  -H "X-SENTINEL-Key: sntl_…" \
  -H "Content-Type: application/json" \
  -d '{
        "allowlist": ["Martin & Associés", "Projet Chimère"],
        "min_confidence": {"PERSON": 0.8},
        "actions": {"LOCATION": "ALLOW"}
      }'
```

| Levier | Effet |
|:---|:---|
| `allowlist` | Valeurs qui ne doivent **jamais** être interceptées : raison sociale, noms de produits, vocabulaire métier |
| `min_confidence` | Seuil de confiance **par type** : durcir sur les noms sans toucher aux IBAN, dont la détection est mathématique |
| `actions` | Action imposée par type : `ALLOW`, `TOKENIZE` ou `BLOCK` |

`GET /policy` renvoie la politique en vigueur.

### La correspondance des exceptions est exacte

Une exception s'applique quand la valeur détectée est **exactement** la
valeur listée, à la casse, aux accents et aux séparateurs près :
« Martin & Associés » couvre « martin et associes », mais **pas**
« Martin Dupont ».

C'est délibéré. Une correspondance partielle supprimerait silencieusement
des détections voisines — un client ajoutant « Martin » cesserait de
protéger toutes les personnes portant ce nom, sans s'en apercevoir. Sur
un contrôle de sécurité, prévisible vaut mieux qu'astucieux.

## Deux garde-fous

Régler, c'est aussi pouvoir affaiblir. Le client reste souverain sur sa
politique — mais jamais discrètement.

**1. Toute modification est scellée dans le journal d'audit** (action
`POLICY_UPDATE`), avec la politique appliquée et les dégradations
détectées. Baisser sa protection est un droit ; le faire sans trace, non.

**2. Les dégradations remontent dans le rapport de conformité.** Sont
signalés : un type critique laissé passer (`SECRET`, `IP_LEAK` en
`ALLOW`), un seuil supérieur à 0,95, une liste d'exceptions de plus de
200 entrées. Le DPO voit qu'un contrôle a été relâché — sans qu'aucune
valeur d'exception ne soit divulguée dans le rapport.

## Mesurer l'effet du réglage

La métrique `sentinel_policy_suppressed_total{reason}` compte les
détections écartées, avec le motif (`exception` ou `sous le seuil`).
C'est le chiffre à suivre après un réglage : il dit combien de
frictions ont disparu, et alerte s'il explose — signe qu'une exception
est trop large.

## Méthode recommandée pour un déploiement

1. **Démarrez sans politique.** Laissez tourner une semaine en mode
   analyse (`/gateway/scan`) et regardez le flux du dashboard.
2. **Relevez les faux positifs récurrents** : ils sont presque toujours
   peu nombreux et très répétitifs (raison sociale, noms de produits,
   quelques villes).
3. **Ajoutez-les en exceptions**, une par une, plutôt que de relever un
   seuil : une exception est ciblée et lisible, un seuil dégrade en
   aveugle une catégorie entière.
4. **Ne touchez aux seuils qu'en dernier recours**, et jamais sur les
   types validés par somme de contrôle (IBAN, carte, NIR) : sur ceux-là,
   un faux positif est quasi impossible par construction.
5. **Ne mettez jamais `SECRET` en `ALLOW`.** Si des secrets techniques
   circulent légitimement, la réponse est de les sortir des prompts, pas
   de cesser de les voir.

## Limites connues

- **Pas d'expressions régulières dans les exceptions.** Uniquement des
  valeurs littérales : une regex mal écrite désactiverait la protection
  bien au-delà de l'intention.
- **Pas d'historique des politiques.** Le journal d'audit conserve chaque
  changement (donc la trace est là), mais il n'existe pas encore de vue
  « qui a changé quoi, quand » ni de retour arrière en un clic.
- **Réglage par client, pas par utilisateur ni par équipe.** Un client
  SENTINEL correspond à une organisation.
