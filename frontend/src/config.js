// En dev : appel direct au backend local. 127.0.0.1 plutôt que localhost :
// sur Windows, localhost peut résoudre en IPv6 et toucher un autre process
// (ex. un conteneur Docker publié sur le même port).
// En prod (Docker) : passe par le proxy nginx sur /api.
const isDev = import.meta.env.DEV;

export const API_BASE = isDev ? "http://127.0.0.1:8000" : "/api";
export const WS_URL = isDev
  ? "ws://127.0.0.1:8000/dashboard/ws"
  : `ws://${window.location.host}/api/dashboard/ws`;