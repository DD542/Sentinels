// En dev : appel direct au backend local. 127.0.0.1 plutôt que localhost :
// sur Windows, localhost peut résoudre en IPv6 et toucher un autre process
// (ex. un conteneur Docker publié sur le même port).
//
// En production, la console et l'API sont servies sur la MÊME origine
// (nginx relaie /api vers le backend) : pas de CORS à ouvrir, et le
// cookie de session reste `SameSite`. VITE_API_BASE permet malgré tout
// de pointer une API sur un autre domaine — il faut alors déclarer
// l'origine de la console dans `cors_origins` côté backend.
const isDev = import.meta.env.DEV;

export const API_BASE =
  import.meta.env.VITE_API_BASE?.replace(/\/$/, "") ??
  (isDev ? "http://127.0.0.1:8000" : "/api");

// Le protocole du WebSocket doit suivre celui de la page. En `ws://` sur
// une page servie en HTTPS, le navigateur bloque la connexion comme
// contenu mixte — le flux temps réel restait muet sur tout déploiement
// avec certificat, sans message d'erreur exploitable.
function wsUrl() {
  if (isDev) return "ws://127.0.0.1:8000/dashboard/ws";
  const absolue = /^https?:\/\//.test(API_BASE);
  const base = absolue ? API_BASE : `${window.location.origin}${API_BASE}`;
  return `${base.replace(/^http/, "ws")}/dashboard/ws`;
}

export const WS_URL = wsUrl();
