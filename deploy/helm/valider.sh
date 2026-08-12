#!/usr/bin/env bash
#
# Valide le chart Helm exactement comme la CI, en local.
#
# Deux validations, complémentaires :
#
#   * kubeconform  — conformité au SCHÉMA Kubernetes : types des champs,
#     champs obligatoires, et en mode strict les champs inconnus. Une
#     faute de frappe comme `replicaCount` au lieu de `replicas`
#     s'appliquerait sans erreur et serait simplement ignorée par le
#     cluster ; c'est ce mode qui la voit.
#   * valider_rendu.py — cohérence du CHART : un manifeste peut être
#     parfaitement conforme au schéma et pointer vers un Service qui
#     n'existe pas.
#
# Les deux travaillent hors ligne (kubeconform télécharge les schémas).
# `kubectl apply --dry-run=client` n'est pas utilisé : il contacte le
# serveur d'API pour résoudre les types et échoue sans cluster.
#
# Prérequis : helm, kubeconform, python + pyyaml.
#   winget install Helm.Helm YannHamon.kubeconform
#
# Usage :  ./deploy/helm/valider.sh
set -euo pipefail

CHART="$(cd "$(dirname "${BASH_SOURCE[0]}")/sentinel" && pwd)"
RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SORTIE="$(mktemp -d)"
trap 'rm -rf "$SORTIE"' EXIT

CATALOGUE_CRD='https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'

echo "==> helm lint"
helm lint --strict "$CHART"

echo
echo "==> Rendu des combinaisons de valeurs"

helm template sentinel "$CHART" > "$SORTIE/rendu-defaut.yaml"
echo "  defaut"

helm template sentinel "$CHART" \
  --set ingress.enabled=true \
  --set autoscaling.enabled=true \
  --set serviceMonitor.enabled=true \
  --set networkPolicy.enabled=true \
  --set secrets.create=true \
  --set secrets.values.auditHmacKey=test \
  > "$SORTIE/rendu-complet.yaml"
echo "  tout active"

helm template sentinel "$CHART" \
  --set dashboard.enabled=false \
  --set ingress.enabled=true \
  > "$SORTIE/rendu-sans-console.yaml"
echo "  sans console"

helm template sentinel "$CHART" \
  --set networkPolicy.enabled=true \
  --set 'networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.kubernetes\.io/metadata\.name=ingress-nginx' \
  > "$SORTIE/rendu-netpol.yaml"
echo "  NetworkPolicy restrictive"

echo
echo "==> Conformite au schema Kubernetes (kubeconform)"
kubeconform -strict -summary \
  -schema-location default \
  -schema-location "$CATALOGUE_CRD" \
  "$SORTIE"/rendu-*.yaml

echo
echo "==> Coherence du chart"
python "$RACINE/deploy/helm/valider_rendu.py" "$SORTIE"/rendu-*.yaml

echo
echo "Chart valide."
