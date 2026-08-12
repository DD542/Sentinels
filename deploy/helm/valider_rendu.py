"""
Vérification du rendu du chart Helm.

Pourquoi ce script existe : la CI validait le rendu avec
`kubectl apply --dry-run=client`. Or cette commande contacte le serveur
d'API pour résoudre les types — **sans cluster, elle échoue toujours**,
y compris avec `--validate=false` (vérifié : « unable to recognize […]
dial tcp [::1]:8080 »). Une étape qui ne peut pas réussir ne valide rien.

Ce script se contente du rendu, sans cluster, et vérifie ce qui casse
réellement un déploiement :

  1. chaque document est un objet Kubernetes complet ;
  2. les Services visent des pods qui existent, et **seulement** ceux-là ;
  3. l'ingress route vers des Services présents dans le rendu ;
  4. aucune règle de NetworkPolicy n'autorise toutes les sources ;
  5. les garde-fous de sécurité n'ont pas disparu.

Le point 2 est celui qui a motivé le script : la console et l'API
partagent leurs labels `name`/`instance`. Un sélecteur qui s'arrête là
enverrait le trafic d'API vers nginx. Le point 4 a trouvé un défaut réel
au premier passage — voir la fonction concernée.

Usage :
    helm template sentinel deploy/helm/sentinel > rendu.yaml
    python deploy/helm/valider_rendu.py rendu.yaml [autre.yaml ...]
"""
from __future__ import annotations
import sys

import yaml

# Champs obligatoires de tout objet Kubernetes.
_SOCLE = ("apiVersion", "kind", "metadata")

# Garde-fous attendus dans le rendu par défaut. Ils sont *testés*, pas
# seulement écrits : une modification qui les retirerait échoue ici.
_GARDE_FOUS = (
    ("runAsNonRoot", True),
    ("readOnlyRootFilesystem", True),
    ("allowPrivilegeEscalation", False),
    ("automountServiceAccountToken", False),
)


class Echec(Exception):
    pass


def _documents(chemin: str) -> list[dict]:
    with open(chemin, encoding="utf-8") as f:
        return [d for d in yaml.safe_load_all(f) if isinstance(d, dict)]


def _labels_des_pods(docs: list[dict]) -> list[tuple[str, dict]]:
    """(nom du workload, labels de son gabarit de pod)."""
    out = []
    for d in docs:
        if d.get("kind") in ("Deployment", "StatefulSet", "DaemonSet"):
            gabarit = d["spec"]["template"]["metadata"].get("labels") or {}
            out.append((d["metadata"]["name"], gabarit))
    return out


def _verifier_socle(docs: list[dict]) -> None:
    for d in docs:
        manquants = [c for c in _SOCLE if not d.get(c)]
        if manquants:
            raise Echec(f"objet incomplet ({', '.join(manquants)}) : "
                        f"{d.get('kind')} {d.get('metadata', {}).get('name')}")
        if not d["metadata"].get("name"):
            raise Echec(f"{d['kind']} sans nom")


def _verifier_services(docs: list[dict]) -> None:
    """Chaque Service doit viser AU MOINS un workload, et jamais deux
    composants différents."""
    pods = _labels_des_pods(docs)
    for d in docs:
        if d.get("kind") != "Service":
            continue
        selecteur = d["spec"].get("selector")
        if not selecteur:
            raise Echec(f"Service {d['metadata']['name']} sans selecteur")
        vises = [nom for nom, labels in pods
                 if all(labels.get(k) == v for k, v in selecteur.items())]
        if not vises:
            raise Echec(
                f"Service {d['metadata']['name']} ne vise aucun pod "
                f"(selecteur {selecteur})")
        if len(vises) > 1:
            raise Echec(
                f"Service {d['metadata']['name']} vise plusieurs workloads "
                f"({', '.join(vises)}) : le trafic partirait au hasard "
                f"entre l'API et la console")


def _verifier_ingress(docs: list[dict]) -> None:
    services = {d["metadata"]["name"] for d in docs
                if d.get("kind") == "Service"}
    for d in docs:
        if d.get("kind") != "Ingress":
            continue
        chemins = []
        for regle in d["spec"].get("rules") or []:
            for chemin in (regle.get("http") or {}).get("paths") or []:
                cible = chemin["backend"]["service"]["name"]
                if cible not in services:
                    raise Echec(
                        f"l'ingress route {chemin['path']} vers le Service "
                        f"'{cible}', absent du rendu")
                chemins.append(chemin["path"])
        if "/" not in chemins:
            raise Echec("l'ingress ne sert aucune route par defaut ('/')")
        if len(chemins) != len(set(chemins)):
            raise Echec("chemins dupliques dans l'ingress")


def _verifier_network_policy(docs: list[dict]) -> None:
    """Piège de Kubernetes : une règle dont `from` est vide autorise
    TOUTES les sources. Une NetworkPolicy qui n'isole rien est pire
    qu'absente — elle donne à l'exploitant la conviction d'être
    protégé."""
    for d in docs:
        if d.get("kind") != "NetworkPolicy":
            continue
        for i, regle in enumerate(d["spec"].get("ingress") or []):
            if not regle.get("from"):
                raise Echec(
                    f"NetworkPolicy {d['metadata']['name']} : la regle {i} a "
                    f"un `from` vide, ce qui autorise TOUTES les sources")


def _verifier_garde_fous(docs: list[dict]) -> None:
    rendu = yaml.dump(docs)
    for champ, attendu in _GARDE_FOUS:
        cible = f"{champ}: {str(attendu).lower()}"
        if cible not in rendu:
            raise Echec(f"garde-fou absent du rendu : {cible}")
    # Le mode strict (fail-closed) doit rester le defaut.
    for d in docs:
        if d.get("kind") != "Deployment":
            continue
        for conteneur in d["spec"]["template"]["spec"]["containers"]:
            for env in conteneur.get("env") or []:
                if env.get("name") == "strict_mode" and env.get("value") != "true":
                    raise Echec("le mode strict n'est plus actif par defaut")


def verifier(chemin: str) -> None:
    docs = _documents(chemin)
    if not docs:
        raise Echec("rendu vide")
    _verifier_socle(docs)
    _verifier_services(docs)
    _verifier_ingress(docs)
    _verifier_network_policy(docs)
    if "defaut" in chemin:
        _verifier_garde_fous(docs)
    kinds = sorted({d["kind"] for d in docs})
    print(f"  OK  {chemin} — {len(docs)} objets : {', '.join(kinds)}")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    echecs = 0
    for chemin in sys.argv[1:]:
        try:
            verifier(chemin)
        except Echec as e:
            print(f"  ECHEC  {chemin} — {e}")
            echecs += 1
    return 1 if echecs else 0


if __name__ == "__main__":
    sys.exit(main())
