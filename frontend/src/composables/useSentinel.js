import { ref, reactive, onMounted, onUnmounted } from "vue";
import { API_BASE, WS_URL } from "../config";

export function useSentinel() {
  const connected = ref(false);
  const auditIntegrity = ref(true);
  const stats = reactive({
    prompts_scanned: 0,
    requests_blocked: 0,
    entities_tokenized: 0,
    secrets_blocked: 0,
    ip_leaks_blocked: 0,
    by_type: {},
  });
  const feed = ref([]); // événements récents (décisions)

  let ws = null;
  let reconnectTimer = null;

  function applySnapshot(snap) {
    if (snap.stats) Object.assign(stats, snap.stats);
    if (snap.recent) {
      feed.value = snap.recent.filter((e) => e.kind === "decision").slice(0, 40);
    }
  }

  function handleEvent(evt) {
    if (evt.kind === "snapshot") {
      applySnapshot(evt);
      return;
    }
    if (evt.kind === "scan") {
      stats.prompts_scanned += 1;
      return;
    }
    if (evt.kind === "decision") {
      feed.value = [evt, ...feed.value].slice(0, 40);
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
    ws = new WebSocket(WS_URL);
    ws.onopen = () => { connected.value = true; };
    ws.onmessage = (e) => handleEvent(JSON.parse(e.data));
    ws.onclose = () => {
      connected.value = false;
      reconnectTimer = setTimeout(connect, 2000); // reconnexion auto
    };
    ws.onerror = () => ws && ws.close();
  }

  async function loadInitial() {
    try {
      const r = await fetch(`${API_BASE}/dashboard/stats`);
      const data = await r.json();
      applySnapshot(data);
      auditIntegrity.value = data.audit_integrity;
    } catch (_) { /* backend pas prêt : le WS prendra le relais */ }
  }

  onMounted(() => { loadInitial(); connect(); });
  onUnmounted(() => {
    if (ws) ws.close();
    if (reconnectTimer) clearTimeout(reconnectTimer);
  });

  return { connected, auditIntegrity, stats, feed };
}