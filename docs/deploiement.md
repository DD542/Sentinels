# Déploiement de SENTINEL en production

> Ce guide couvre le déploiement Kubernetes via Helm et la chaîne
> d'approvisionnement (scan d'image, SBOM). Pour un essai local,
> `docker compose up` suffit — voir le README.

## Principe : fail-closed par défaut

Le chart active `strictMode` par défaut. SENTINEL **refuse alors de
démarrer** si sa posture est incomplète : persistance absente, clés
cryptographiques laissées à leur valeur par défaut, tokens d'admin ou de
dashboard non définis. Chaque manque est nommé dans les logs.

C'est délibéré : un outil de protection des données qui démarre en mode
dégradé sans le dire est plus dangereux qu'un outil qui ne démarre pas.

## Installation

### 1. Créer le Secret (hors du chart)

Ne placez jamais de secret dans un `values.yaml` : il finirait versionné.
Le chart lit un Secret existant.

```bash
kubectl create namespace sentinel

kubectl -n sentinel create secret generic sentinel \
  --from-literal=vault_master_key=$(openssl rand -hex 32) \
  --from-literal=audit_hmac_key=$(openssl rand -hex 32) \
  --from-literal=admin_token=$(openssl rand -hex 24) \
  --from-literal=dashboard_token=$(openssl rand -hex 24) \
  --from-literal=database_url='postgresql://user:pass@hote:5432/sentinel' \
  --from-literal=groq_api_key='…'
```

En entreprise, préférez un gestionnaire de secrets (External Secrets
Operator, Vault, SOPS) qui produit ce même Secret.

> **Les clés cryptographiques ne se régénèrent pas.** Changer
> `vault_master_key` rend les jetons existants irrécupérables ; changer
> `audit_hmac_key` casse la vérification de la chaîne d'audit **et** rend
> illisibles tous les détails déjà chiffrés. Sauvegardez-les comme vous
> sauvegarderiez une clé de chiffrement de base de données.

### 2. Installer le chart

```bash
helm install sentinel deploy/helm/sentinel \
  -n sentinel \
  --set secrets.existingSecret=sentinel \
  --set image.tag=0.1.0 \
  --set config.corsOrigins=https://sentinel.mondomaine.fr \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=sentinel.mondomaine.fr
```

Le chart déploie **l'API et la console**. Un seul nom d'hôte suffit : les
chemins de l'API (`/v1`, `/gateway`, `/admin`, `/auth`…) vont au backend,
tout le reste à la console. La console relaie elle-même `/api` vers
l'API — donc sur la même origine, ce qui évite d'ouvrir le CORS et
conserve un cookie de session `SameSite`.

`dashboard.enabled=false` déploie l'API seule (intégration par API
uniquement, sans interface).

### 3. Vérifier

```bash
kubectl -n sentinel get pods
kubectl -n sentinel port-forward svc/sentinel 8000:8000
curl -s localhost:8000/health

# La console
kubectl -n sentinel port-forward svc/sentinel-dashboard 8080:80
```

## Ce que le chart applique

| Garde-fou | Valeur | Pourquoi |
|:---|:---|:---|
| `runAsNonRoot`, UID 1000 | activé | Aucun processus root dans le conteneur |
| `readOnlyRootFilesystem` | activé | Un attaquant ne peut rien écrire ; `/tmp` est un volume dédié |
| `allowPrivilegeEscalation` | désactivé | Interdit l'élévation via setuid |
| `capabilities: drop ALL` | activé | Aucune capacité Linux n'est nécessaire |
| `automountServiceAccountToken` | désactivé | SENTINEL n'appelle pas l'API Kubernetes |
| `seccompProfile: RuntimeDefault` | activé | Filtrage des appels système |
| Sondes `/health` | liveness, readiness, startup | Le modèle de langue met du temps à charger : la sonde de démarrage évite les faux redémarrages |
| PodDisruptionBudget | `minAvailable: 1` | La passerelle reste disponible pendant les opérations sur le cluster |

Options désactivées par défaut, à activer selon votre contexte :
`ingress`, `autoscaling`, `serviceMonitor` (Prometheus Operator) et
`networkPolicy`.

> **NetworkPolicy — un piège de Kubernetes.** Une règle dont le champ
> `from` est vide autorise *toutes* les sources. Le chart émettait cette
> règle dès que `networkPolicy.enabled=true`, même sans source déclarée :
> la policy semblait isoler l'API et ne l'isolait pas. Corrigé — sans
> `ingressFrom`, aucune règle n'est émise et seule la console peut
> joindre l'API. Déclarez vos sources explicitement :
>
> ```yaml
> networkPolicy:
>   enabled: true
>   ingressFrom:
>     - namespaceSelector:
>         matchLabels: {kubernetes.io/metadata.name: ingress-nginx}
> ```

## Origines autorisées (CORS)

`config.corsOrigins` liste les origines autorisées à appeler l'API depuis
un navigateur. **En mode strict, un déploiement sans cette valeur refuse
de démarrer** : le défaut n'autorise que `localhost`, et une console
servie sur votre domaine se heurterait à un blocage CORS silencieux.

```yaml
config:
  corsOrigins: "https://sentinel.mondomaine.fr"
```

Deux règles :

- Tant que la console est servie par ce chart, elle relaie l'API sur la
  **même origine** : le CORS n'entre pas en jeu pour son propre trafic.
  La valeur reste néanmoins exigée, car d'autres applications internes
  appellent l'API depuis un navigateur.
- **`*` est refusé.** La console s'authentifie par cookie ; une origine
  joker laisserait n'importe quel site visité par un administrateur
  connecté piloter sa session. Les navigateurs rejettent d'ailleurs la
  combinaison — mais silencieusement, ce qui fait chercher la panne
  ailleurs pendant des heures.

## Clés de vault par client (BYOK)

Chaque client a sa propre clé de chiffrement du vault. Par défaut elle
est **dérivée** de `vault_master_key` (HKDF-SHA256, `info` = identifiant
du client) : le cloisonnement entre organisations devient une propriété
cryptographique et non plus une simple clause `WHERE`. Une erreur de
filtrage renvoie alors des lignes illisibles au lieu de données en clair.

Un client peut fournir **sa** clé. SENTINEL ne peut alors plus lire son
vault, même avec un accès complet à la base :

```bash
kubectl -n sentinel create secret generic sentinel-byok \
  --from-literal=vault_client_keys='{"acme-corp":"<64 caractères hex>"}'
```

```yaml
extraEnv:
  - name: vault_client_keys
    valueFrom:
      secretKeyRef: {name: sentinel-byok, key: vault_client_keys}
```

> **À dire au client avant, pas après.** Cette clé perdue, son vault est
> irrécupérable — c'est le prix exact de la garantie qu'il achète. Les
> jetons expirent en `VAULT_TTL_HOURS` (24 h par défaut), donc la perte
> est bornée à une journée d'interactions, pas au journal d'audit, qui
> possède son propre chiffrement.

## Supervision

Le chart peut déclarer un `ServiceMonitor` pour que Prometheus collecte
`/metrics` :

```bash
helm upgrade sentinel deploy/helm/sentinel -n sentinel \
  --reuse-values --set serviceMonitor.enabled=true
```

Métriques utiles pour un tableau de bord RSSI : `sentinel_decisions_total`
(par action, type et couche), `sentinel_scan_duration_seconds`,
`sentinel_rate_limited_total`, `sentinel_audit_chain_entries`.

## Chaîne d'approvisionnement

Un outil de sécurité doit être exemplaire sur la sienne. Le workflow
[`security.yml`](../.github/workflows/security.yml) s'exécute à chaque
push **et chaque lundi** (les CVE apparaissent après la fusion) :

| Étape | Outil | Effet |
|:---|:---|:---|
| Audit des dépendances Python | `pip-audit` | Échec si une dépendance a une vulnérabilité connue |
| Scan de l'image | Trivy | Rapport SARIF publié dans l'onglet *Security* ; **échec** sur une vulnérabilité corrigeable HIGH ou CRITICAL |
| Inventaire logiciel | Syft (CycloneDX) | SBOM publié en artefact, conservé 90 jours |
| Chart Helm | `helm lint --strict`, `helm template` (4 combinaisons de valeurs) | Le chart doit se rendre dans tous les modes : par défaut, tout activé, sans console, avec NetworkPolicy restrictive |
| Rendu du chart | [`valider_rendu.py`](../deploy/helm/valider_rendu.py) | Chaque Service doit viser **un seul** workload, l'ingress ne doit router que vers des Services existants, aucune règle de NetworkPolicy ne doit autoriser toutes les sources, et les garde-fous (`runAsNonRoot`, `readOnlyRootFilesystem`, mode strict) doivent rester présents |

Le dernier point mérite d'être souligné : les garde-fous de sécurité sont
**testés**, pas seulement écrits. Une modification qui désactiverait le
mode strict par défaut fait échouer la CI.

> La validation du rendu utilisait auparavant `kubectl apply
> --dry-run=client`. Cette commande contacte le serveur d'API pour
> résoudre les types : sans cluster — et un runner n'en a pas — elle
> échoue systématiquement, y compris avec `--validate=false`. Elle ne
> validait donc rien. Le script qui l'a remplacée travaille hors ligne,
> et chacune de ses vérifications a été éprouvée en réintroduisant le
> défaut qu'elle est censée attraper.

L'image ne contient pas de compilateur : `gcc` et `g++` sont installés
pour construire les wheels puis purgés dans la même couche.

## Vérifier une image publiée

Les images publiées sur un tag `v*` sont **signées avec cosign sans clé** :
l'identité vient du jeton OIDC de GitHub Actions, il n'y a donc aucune
clé privée à stocker — ni à faire fuiter. Trois éléments sont attachés à
l'empreinte de l'image : la signature, une **provenance SLSA** (quel
dépôt, quel commit, quel workflow) et un **SBOM CycloneDX attesté**.

Avant de déployer, un client peut vérifier que l'image vient bien de ce
dépôt et n'a pas été substituée :

```bash
# Signature et identité du producteur
cosign verify \
  --certificate-identity-regexp '^https://github.com/DD542/Sentinels/.github/workflows/release.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/dd542/sentinel@sha256:<digest>
```

```bash
# Provenance SLSA et SBOM attesté (CLI GitHub)
gh attestation verify oci://ghcr.io/dd542/sentinel@sha256:<digest> \
  --repo DD542/Sentinels
```

```bash
# Contenu du SBOM
cosign download attestation \
  --predicate-type https://cyclonedx.org/bom \
  ghcr.io/dd542/sentinel@sha256:<digest>
```

Le workflow **scanne avant de signer** et **vérifie sa propre
signature** après publication : on ne signe pas une image vulnérable, et
une signature qu'on ne sait pas vérifier ne prouve rien.

Les **deux** images suivent cette chaîne : `ghcr.io/dd542/sentinel` et
`ghcr.io/dd542/sentinel-dashboard`. Une console non signée pendant que
l'API l'est laisserait sans preuve le composant qui reçoit les
identifiants des administrateurs.

## Limites connues du déploiement

- **Image de base non épinglée par empreinte.** `python:3.12-slim` suit
  les correctifs de sécurité, au prix de la reproductibilité stricte.
  Épinglez un digest si votre politique l'exige.
- **La vérification suppose de connaître l'empreinte.** Signature et
  attestations sont attachées au digest, pas au tag : vérifiez
  `image@sha256:…`, pas `image:latest`, qu'un attaquant pourrait
  repointer.
- **Actions GitHub référencées par branche** (`@master` pour Trivy) :
  épinglez un SHA de commit en environnement d'entreprise.
