# SSO d'entreprise pour le dashboard

## Le problème que ça résout

Sans SSO, le dashboard est protégé par un **token partagé**
(`DASHBOARD_TOKEN`). Trois conséquences dont un RSSI se passerait :

- **Aucune responsabilité individuelle.** Le journal peut prouver qu'une
  console a été consultée, jamais *par qui*.
- **Aucun retrait d'accès.** Un employé qui part garde le token ; le
  révoquer impose de le changer pour tout le monde.
- **Aucune authentification forte.** Le token contourne le MFA de
  l'entreprise.

Avec le SSO, chaque connexion est nominative, **scellée dans le journal
d'audit**, soumise à la politique d'authentification de l'entreprise, et
l'accès disparaît avec le compte.

## Pourquoi OIDC et pas SAML

Les deux répondent au même besoin. OIDC a été retenu pour trois raisons :

1. **Surface d'attaque.** SAML impose en Python la chaîne
   `python3-saml`/`xmlsec` et toute une famille de vulnérabilités liées à
   la signature XML (*signature wrapping*), historiquement fertile en
   contournements d'authentification. OIDC vérifie un JWT signé avec des
   clés publiées en JWKS.
2. **Couverture.** Entra ID (Azure AD), Okta, Keycloak, Google Workspace,
   Ping : tous exposent OIDC.
3. **Exploitation.** Pas de bibliothèque C à compiler dans l'image, donc
   pas de compilateur à réintroduire (voir [deploiement.md](deploiement.md)).

**Si votre organisation impose SAML**, placez devant SENTINEL un proxy
d'identité (oauth2-proxy, Pomerium, Entra Application Proxy) : il parle
SAML côté fournisseur et transmet l'identité en aval. SENTINEL reste
alors protégé par son token en réseau interne.

## Configuration

```env
OIDC_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0
OIDC_CLIENT_ID=<identifiant de l'application>
OIDC_CLIENT_SECRET=<secret>
OIDC_REDIRECT_URI=https://sentinel.monentreprise.fr/auth/callback

# OBLIGATOIRE — sans restriction, SENTINEL refuse toute connexion.
OIDC_ALLOWED_DOMAINS=monentreprise.fr
# ou, au choix / en complément :
OIDC_ALLOWED_GROUPS=rssi,dpo

SESSION_TTL_HOURS=8
SESSION_COOKIE_SECURE=true
```

Déclarez `OIDC_REDIRECT_URI` à l'identique chez votre fournisseur
d'identité.

> **Le refus par défaut est délibéré.** Si aucun domaine ni groupe n'est
> configuré, toute connexion est rejetée. Avec un fournisseur public
> (Google Workspace, Entra multi-tenant), l'absence de restriction
> laisserait entrer n'importe quel compte du monde.

## Ce que le flux garantit

| Protection | Mise en œuvre |
|:---|:---|
| Interception du code d'autorisation | **PKCE S256** : le code seul est inutilisable |
| CSRF sur le retour | Paramètre `state` vérifié en temps constant, transporté dans un cookie chiffré |
| Rejeu d'un jeton d'identité | `nonce` vérifié |
| Jeton forgé | Signature vérifiée via **JWKS**, algorithmes autorisés en liste blanche (`alg=none` rejeté) |
| Jeton d'une autre application | `aud` vérifié |
| Jeton d'un autre émetteur | `iss` vérifié |
| Jeton périmé | `exp` et `iat` obligatoires |
| Vol du cookie de session | Cookie **chiffré** (Fernet, clé à domaine séparé), `HttpOnly`, `Secure`, `SameSite=Lax`, expiration à la lecture |
| Redirection ouverte | Le paramètre `next` doit être un chemin interne (`//evil.com` rejeté) |

Chaque connexion — et chaque refus — est scellé dans la chaîne d'audit
(`AUTH_LOGIN`, `AUTH_DENIED`). L'adresse de la personne y est **chiffrée
et indexée en aveugle** : la traçabilité nominative n'entre pas en
conflit avec le droit à l'effacement (voir
[politique-retention.md](politique-retention.md)).

## Accès de secours

`DASHBOARD_TOKEN` reste accepté quand il est défini, même SSO actif. Il
sert à l'automatisation (supervision, export de rapports) et à garder un
accès si le fournisseur d'identité est indisponible. Réservez-le à un
coffre-fort de secrets : c'est un accès non nominatif.

Pour l'interdire complètement, laissez `DASHBOARD_TOKEN` vide une fois le
SSO en place.

## Révocation des sessions

Le cookie est autoportant : il porte sa propre validité, ce qui évite un
aller-retour en base à chaque requête. Sans registre de révocation, une
session ne pourrait donc pas être coupée avant son expiration — un
cookie volé resterait utilisable, et « se déconnecter » n'effacerait le
cookie que dans le navigateur de son propriétaire.

Trois portées sont disponibles :

| Portée | Effet | Usage |
|:---|:---|:---|
| **Session** | Coupe une session précise (`jti`) | La déconnexion l'utilise : le cookie meurt, y compris pour qui en garderait une copie |
| **Compte** | Coupe toutes les sessions d'une personne ouvertes avant la révocation | Départ d'un employé, compte compromis |
| **Globale** | Coupe toutes les sessions | Incident, rotation de clé |

```bash
# Couper les sessions d'une personne (adresse ou identifiant du compte)
curl -X POST http://<sentinel>/auth/revoke \
  -H "Content-Type: application/json" \
  -d '{"admin_token": "<ADMIN_TOKEN>", "subject": "alice@monentreprise.fr"}'
```

```bash
# Tout couper (incident, rotation de clé)
curl -X POST http://<sentinel>/auth/revoke \
  -H "Content-Type: application/json" \
  -d '{"admin_token": "<ADMIN_TOKEN>", "all_sessions": true}'
```

Chaque révocation est scellée dans le journal d'audit. Le registre est
persisté (il survit aux redémarrages) et **borné** : une révocation est
effacée par la maintenance périodique dès que la session visée aurait
expiré d'elle-même.

Une révocation par compte ne coupe que les sessions **antérieures** :
réactiver un compte n'impose pas de défaire quoi que ce soit.

## Limites connues

- **La révocation d'une session est immédiate, celle d'un compte aussi**,
  mais elles reposent sur un registre en mémoire alimenté par la base :
  sans persistance (`DATABASE_URL` vide), une révocation ne survit pas au
  redémarrage.
- **Pas de rafraîchissement de jeton.** À l'expiration, l'utilisateur se
  reconnecte — un aller-retour transparent si la session du fournisseur
  est encore ouverte.
- **En développement**, le dashboard (`localhost:5173`) et l'API
  (`127.0.0.1:8000`) sont deux origines différentes : `SameSite=Lax`
  empêche l'envoi du cookie. Testez le SSO derrière le proxy nginx
  (origine unique), comme en production.
- **SSO du dashboard uniquement.** Les clés API de la passerelle
  (`X-SENTINEL-Key`) restent des secrets applicatifs : elles
  authentifient des machines, pas des personnes.
