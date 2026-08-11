# Rôles et console d'administration

## Le problème

Jusqu'ici, deux choses manquaient. D'abord, **tout se faisait en `curl`** :
créer une clé, lire la consommation, révoquer, vérifier le journal.
Ensuite, **quiconque entrait voyait tout** — le flux des décisions, la
facturation, les clés, l'effacement RGPD. Or ces écrans n'intéressent pas
les mêmes personnes et n'engagent pas les mêmes responsabilités.

## Trois rôles

| Rôle | Qui | Peut |
|:---|:---|:---|
| **administrateur** | Exploitant, RSSI | Tout : clés, consommation facturable, maintenance, conformité, droits RGPD |
| **auditeur** | DPO, contrôle interne, commissaire aux comptes | Rapports de conformité, droits des personnes (accès et effacement), vérification du journal |
| **observateur** | Analyste sécurité, SOC | Flux temps réel uniquement |

Le choix de découpage mérite d'être explicité : **un auditeur ne peut ni
créer une clé, ni lire la facturation**. Un DPO n'a aucune raison de
pouvoir ouvrir un accès à la passerelle, et la consommation par client
relève du contrat, pas du contrôle des données personnelles.

### Permissions

| Permission | administrateur | auditeur | observateur |
|:---|:---:|:---:|:---:|
| `dashboard:read` | ✅ | ✅ | ✅ |
| `compliance:read` | ✅ | ✅ | — |
| `gdpr:manage` | ✅ | ✅ | — |
| `audit:verify` | ✅ | ✅ | — |
| `keys:manage` | ✅ | — | — |
| `usage:read` | ✅ | — | — |
| `maintenance:run` | ✅ | — | — |

## Attribution des rôles

**Avec SSO**, le rôle vient des groupes du fournisseur d'identité :

```env
OIDC_ADMIN_GROUPS=rssi,it-admin
OIDC_AUDITOR_GROUPS=dpo,audit-interne
OIDC_VIEWER_GROUPS=soc,analystes
```

Le rôle le plus fort l'emporte en cas d'appartenance multiple. Un compte
autorisé mais **sans groupe reconnu reçoit le rôle le plus faible** —
une configuration de groupes incomplète ne doit jamais accorder les
droits d'administration par accident.

**Sans SSO**, le rôle vient du jeton présenté : `X-Admin-Token` donne
*administrateur*, `X-Dashboard-Token` donne *observateur*.

> **Le repli « démonstration » n'accorde jamais l'administration.**
> Sans jeton de dashboard ni SSO, la console de *lecture* reste ouverte
> (comportement historique), mais les opérations d'administration
> continuent d'exiger le jeton. Ce point est verrouillé par un test :
> pendant l'implémentation, une première version accordait le rôle
> administrateur dans ce cas — un mauvais jeton serait passé.

## La console

Onglet **Administration** du dashboard. Quatre écrans, chacun visible
seulement si le rôle le permet :

- **Clés clients** — création (affichée une seule fois, stockée hachée)
  et révocation, scellée dans l'audit ;
- **Consommation** — compteurs persistés par client sur 30 jours, la base
  de facturation à l'usage ;
- **Vérification du journal** — complète (relit tout, seule à détecter
  une altération ancienne) ou incrémentale (instantanée, aveugle au
  passé) ;
- **Maintenance** — application des durées de conservation à la demande.

L'onglet lui-même est toujours visible : c'est la porte, pas la salle.
Un opérateur sans SSO y présente son jeton d'administration et la console
lui redemande ses droits au serveur.

> **L'affichage n'est pas la sécurité.** La console masque ce qui n'est
> pas autorisé par confort, mais **le serveur revérifie chaque
> permission** à chaque appel. Masquer un bouton n'a jamais protégé une
> API.

## Compatibilité

Les endpoints d'administration acceptent **les deux voies** : le jeton
(automatisation, scripts, supervision — rien ne casse) ou une session
dont le rôle possède la permission. Sans cela, la console devrait
redemander le jeton admin à chaque action, et les utilisateurs finiraient
par le coller dans un onglet de navigateur.

## Limites connues

- **Trois rôles fixes.** Pas de rôles personnalisés ni de permissions à
  la carte : c'est suffisant pour les fonctions réelles observées, et une
  matrice configurable serait une surface d'erreur supplémentaire sur un
  contrôle d'accès.
- **Pas de cloisonnement par client dans la console.** Un administrateur
  voit tous les clients. Pour du SaaS mutualisé où chaque organisation
  administrerait elle-même, il faudrait lier le rôle à un `client_id`.
- **Le rôle est figé pour la durée de la session.** Un changement de
  groupe chez le fournisseur d'identité prend effet à la reconnexion, ou
  immédiatement si l'on révoque la session (voir [sso.md](sso.md)).
