// En dev : appel direct au backend local.
// En prod (Docker) : passe par le proxy nginx sur /api.
const isDev = import.meta.env.DEV;

export const API_BASE = isDev ? "http://localhost:8000" : "/api";
export const WS_URL = isDev
  ? "ws://localhost:8000/dashboard/ws"
  : `ws://${window.location.host}/api/dashboard/ws`;