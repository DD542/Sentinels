# SENTINEL — Cartographie de conformité (AI Act & RGPD)

> **Avertissement.** Ce document cartographie la contribution technique de
> SENTINEL aux obligations réglementaires. Il ne constitue **pas un avis
> juridique** et un outil ne rend **jamais** une organisation conforme à lui
> seul : la conformité reste un processus organisationnel (gouvernance,
> analyses d'impact, bases légales, contrats). Faire valider ce mapping par
> votre DPO ou votre conseil.

## Positionnement

Le règlement (UE) 2024/1689 (« AI Act ») est entré en vigueur le
1ᵉʳ août 2024 et s'applique par étapes ; l'essentiel des obligations est
applicable au **2 août 2026**. SENTINEL se place du côté **déployeur** :
l'entreprise dont les employés utilisent des systèmes d'IA tiers (ChatGPT,
Claude, Copilot…). SENTINEL n'est pas lui-même un système d'IA à haut
risque : c'est une passerelle de contrôle des données qui **outille** les
obligations du déployeur.

## Contribution aux obligations de l'AI Act

| Obligation (AI Act) | Ce que SENTINEL apporte | Limite |
|:---|:---|:---|
| **Art. 4 — Maîtrise de l'IA.** Le déployeur s'assure d'un usage maîtrisé des systèmes d'IA. | Le **registre Shadow AI** rend visibles les usages réels : quel fournisseur, quelle région, quels volumes. On ne maîtrise que ce qu'on voit. | La sensibilisation des employés reste à la charge de l'organisation. |
| **Art. 26(4) — Contrôle des données d'entrée** (systèmes à haut risque : données pertinentes et suffisamment représentatives). | Chaque prompt sortant est **inspecté avant transmission** ; données personnelles pseudonymisées, secrets bloqués, documents confidentiels interceptés. | SENTINEL contrôle la *sensibilité* des entrées, pas leur *pertinence métier*. |
| **Art. 26(6) — Conservation des journaux** générés par le système (au moins 6 mois pour les systèmes à haut risque). | **Journal d'audit chaîné HMAC-SHA256**, persistant (Postgres), dont l'intégrité est vérifiable à tout moment ; chaque décision est scellée et horodatée. | La durée de rétention est à configurer selon votre politique. |
| **Art. 14 — Contrôle humain** (le déployeur confie la surveillance à des personnes compétentes). | **Dashboard temps réel** (flux des décisions, drapeaux d'évasion) donnant au RSSI la visibilité opérationnelle ; les tentatives de contournement sont tracées nominativement par clé client. | L'organisation doit désigner et former les personnes en charge. |
| **Art. 12 — Enregistrement** (traçabilité des systèmes à haut risque, côté fournisseur). | Côté déployeur, SENTINEL fournit la **traçabilité d'usage** complémentaire : qui a envoyé quoi, quand, vers quel fournisseur, avec quelle décision. | Les logs internes du système d'IA lui-même relèvent de son fournisseur. |

## Contribution aux obligations du RGPD

| Obligation (RGPD) | Ce que SENTINEL apporte | Limite |
|:---|:---|:---|
| **Art. 4(5) & 32 — Pseudonymisation.** | **Tokenisation à format préservé (FPE)** : le fournisseur d'IA ne reçoit que des substituts factices ; la table de correspondance reste chez vous, chiffrée. C'est la définition exacte de la pseudonymisation de l'art. 4(5). | Une donnée non détectée part en clair — voir [Limites connues](../README.md#limites-connues). |
| **Art. 5(1)(c) — Minimisation.** | Seul le texte utile, débarrassé des données identifiantes, quitte l'entreprise. | — |
| **Art. 15 — Droit d'accès.** | `POST /compliance/subject` renvoie, pour une personne, le nombre d'entrées, les types de données concernés et la période — en métadonnées, sans jamais déchiffrer une valeur. La personne est retrouvée par **index aveugle** (HMAC), son identité n'étant nulle part stockée. | Suppose de connaître la valeur exacte à rechercher. |
| **Art. 17 — Droit à l'effacement.** | **Crypto-shredding** visant une personne (`POST /compliance/forget-subject`) ou une entité technique (`POST /compliance/forget`) : chaque entité possède une clé de chiffrement **aléatoire** (Fernet), stockée enveloppée par une clé maître. Détruire cette clé rend ses données définitivement illisibles — y compris pour l'exploitant — sans réécrire le journal ni casser la chaîne de hachage. Voir [politique-retention.md](politique-retention.md). | L'effacement chez le fournisseur d'IA tiers relève de votre contrat avec lui. |
| **Art. 25 — Protection dès la conception.** | L'architecture même (passerelle interposée, détection par défaut, fail-safe) matérialise le *privacy by design* pour les flux IA. | — |
| **Art. 30 — Registre des traitements.** | Modèle de registre **pré-rempli** pour le traitement « passerelle IA » : [registre-rgpd.md](registre-rgpd.md). | À compléter avec vos informations (responsable, DPO, durées). |
| **Art. 32 — Sécurité du traitement.** | Chiffrement au repos (Fernet), clés API stockées hachées, journal inviolable, authentification multi-clients, rate-limiting, comparaisons en temps constant. | La sécurité de l'infrastructure d'hébergement vous incombe. |
| **Chap. V (art. 44 et s.) — Transferts hors UE.** | Le **registre Shadow AI** documente, par fournisseur, la région de traitement et le volume de requêtes — la matière première de votre analyse de transfert. | La qualification juridique du transfert (DPA, SCC) reste contractuelle. |
| **Art. 33/34 — Violations de données.** | Le journal d'audit signé fournit la **chronologie opposable** : quelles données sont sorties, quand, sous quelle forme (pseudonymisée ou bloquée). | La notification à la CNIL reste un processus organisationnel. |

## Livrables associés

- **Rapport de conformité signé** : `GET /compliance/report` (HTML imprimable
  en PDF) et `GET /compliance/report.json` (canonique, signé HMAC-SHA256 —
  re-vérifiable par l'exploitant, seul détenteur de la clé d'audit).
- **Registre RGPD pré-rempli** : [registre-rgpd.md](registre-rgpd.md).
- **Politique de conservation** : [politique-retention.md](politique-retention.md)
  — ce qui est stocké, sous quelle forme, combien de temps, et comment
  l'effacer (crypto-shredding).
- **Benchmark public** de détection : voir README, section
  « Benchmark externe ».

## Ce que SENTINEL ne fait pas

En toute transparence : pas d'analyse de risque IA automatisée, pas d'AIPD
(DPIA) générée, pas de qualification juridique des bases légales, pas de
garantie de détection exhaustive. Ces limites existent dans toutes les
solutions du marché — y compris celles qui ne les affichent pas.
