import { ref, reactive, onMounted, onUnmounted } from "vue";
import { API_BASE, WS_URL } from "../config";

const TOKEN_KEY = "sentinel_dashboard_token";

export function useSentinel() {
  const connected = ref(false);
  const authRequired = ref(false);
  const ssoEnabled = ref(false);
  const role = ref(null);
  const permissions = ref([]);
  const identity = ref(null);
  const loginUrl = ref(`${API_BASE}/auth/login`);
  const auditIntegrity = ref(true);
  const stats = reactive({
    prompts_scanned: 0,
    requests_blocked: 0,
    entities_tokenized: 0,
    secrets_blocked: 0,
    ip_leaks_blocked: 0,
    by_type: {},
    by_provider: {},
  });
  const feed = ref([]);
  const scans = ref([]);

  let ws = null;
  let reconnectTimer = null;

  function getToken() {
    return localStorage.getItem(TOKEN_KEY) || "";
  }

  function applySnapshot(snap) {
    if (snap.stats) Object.assign(stats, snap.stats);
    if (snap.recent) {
      feed.value = snap.recent.filter((e) => e.kind === "decision").slice(0, 60);
      scans.value = snap.recent.filter((e) => e.kind === "scan").map((e) => e.ts).slice(0, 200);
    }
  }

  function handleEvent(evt) {
    if (evt.kind === "snapshot") { applySnapshot(evt); return; }
    if (evt.kind === "scan") {
      stats.prompts_scanned += 1;
      scans.value = [evt.ts, ...scans.value].slice(0, 200);
      return;
    }
    if (evt.kind === "provider") {
      const p = evt.provider || "?";
      stats.by_provider[p] = (stats.by_provider[p] || 0) + 1;
      return;
    }
    if (evt.kind === "decision") {
      feed.value = [evt, ...feed.value].slice(0, 60);
      const t = evt.entity_type || "?";
      if (evt.action === "TOKENIZE") {
        stats.entities_tokenized += 1;
        stats.by_type[t] = (stats.by_type[t] || 0) + 1;
      } else if (evt.action === "BLOCK") {
        stats.secrets_blocked += 1;
        stats.by_type[t] = (stats.by_type[t] || 0) + 1;
      } else if (evt.action === "BLOCK_REQUEST") {
        stats.requests_blocked += 1;
        stats.ip_leaks_blocked += 1;
      }
    }
  }

  function connect() {
    // Le token passe en second sous-protocole ("sentinel.v1", token) :
    // seul moyen pour un navigateur d'authentifier un WebSocket sans
    // exposer le secret dans l'URL.
    const token = getToken();
    ws = token ? new WebSocket(WS_URL, ["sentinel.v1", token]) : new WebSocket(WS_URL);
    ws.onopen = () => { connected.value = true; authRequired.value = false; };
    ws.onmessage = (e) => handleEvent(JSON.parse(e.data));
    ws.onclose = (e) => {
      connected.value = false;
      // 1008 = token refusé côté serveur : on arrête de marteler et on
      // affiche l'écran de saisie du token.
      if (e.code === 1008 || authRequired.value) {
        authRequired.value = true;
        return;
      }
      reconnectTimer = setTimeout(connect, 2000);
    };
    ws.onerror = () => ws && ws.close();
  }

  async function loadInitial() {
    try {
      const token = getToken();
      const r = await fetch(`${API_BASE}/dashboard/stats`, {
        headers: token ? { "X-Dashboard-Token": token } : {},
        credentials: "include", // porte la session SSO
      });
      if (r.status === 401) { authRequired.value = true; return; }
      const data = await r.json();
      applySnapshot(data);
      auditIntegrity.value = data.audit_integrity;
    } catch (_) { /* backend pas prêt */ }
  }

  function setToken(token) {
    localStorage.setItem(TOKEN_KEY, token.trim());
    authRequired.value = false;
    if (ws) ws.close();
    if (reconnectTimer) clearTimeout(reconnectTimer);
    loadInitial();
    connect();
  }

  // Qui suis-je et que puis-je faire ? La console n'affiche que les
  // ecrans autorises — le serveur refait le controle de toute facon.
  async function loadIdentity(adminToken) {
    try {
      const headers = {};
      if (adminToken) headers["X-Admin-Token"] = adminToken;
      const r = await fetch(`${API_BASE}/auth/me`, {
        credentials: "include", headers,
      });
      const me = await r.json();
      role.value = me.role;
      permissions.value = me.permissions || [];
      identity.value = me.email || me.name || null;
    } catch (_) { /* backend pas pret */ }
  }

  function can(permission) {
    return permissions.value.includes(permission);
  }

  async function loadAuthConfig() {
    try {
      const r = await fetch(`${API_BASE}/auth/config`, { credentials: "include" });
      const cfg = await r.json();
      ssoEnabled.value = !!cfg.sso_enabled;
      if (cfg.login_url) loginUrl.value = `${API_BASE}${cfg.login_url}`;
    } catch (_) { /* backend pas prêt */ }
  }

  async function logout() {
    try {
      await fetch(`${API_BASE}/auth/logout`, {
        method: "POST", credentials: "include",
      });
    } catch (_) { /* ignore */ }
    localStorage.removeItem(TOKEN_KEY);
    authRequired.value = true;
  }

  onMounted(() => {
    loadAuthConfig(); loadIdentity(); loadInitial(); connect();
  });
  onUnmounted(() => {
    if (ws) ws.close();
    if (reconnectTimer) clearTimeout(reconnectTimer);
  });

  return { connected, authRequired, ssoEnabled, loginUrl, auditIntegrity,
           role, permissions, identity, can, loadIdentity,
           stats, feed, scans, setToken, logout };
}
