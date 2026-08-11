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
  --set image.repository=ghcr.io/dd542/sentinel \
  --set image.tag=0.1.0
```

### 3. Vérifier

```bash
kubectl -n sentinel get pods
kubectl -n sentinel port-forward svc/sentinel 8000:8000
curl -s localhost:8000/health
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
| Chart Helm | `helm lint`, `helm template`, `kubectl --dry-run` | Le rendu doit être du Kubernetes valide |
| Garde-fous du chart | `grep` sur le rendu | Échec si `runAsNonRoot`, `readOnlyRootFilesystem` ou le mode strict disparaissent d'une modification |

Le dernier point mérite d'être souligné : les garde-fous de sécurité sont
**testés**, pas seulement écrits. Une modification qui désactiverait le
mode strict par défaut fait échouer la CI.

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
  ghcr.io/dd542/sentinels@sha256:<digest>
```

```bash
# Provenance SLSA et SBOM attesté (CLI GitHub)
gh attestation verify oci://ghcr.io/dd542/sentinels@sha256:<digest> \
  --repo DD542/Sentinels
```

```bash
# Contenu du SBOM
cosign download attestation \
  --predicate-type https://cyclonedx.org/bom \
  ghcr.io/dd542/sentinels@sha256:<digest>
```

Le workflow **scanne avant de signer** et **vérifie sa propre
signature** après publication : on ne signe pas une image vulnérable, et
une signature qu'on ne sait pas vérifier ne prouve rien.

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
