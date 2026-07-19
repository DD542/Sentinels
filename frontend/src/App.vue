<script setup>
import { computed, ref } from "vue";
import { useSentinel } from "./composables/useSentinel";
import { API_BASE } from "./config";

const { connected, authRequired, auditIntegrity, stats, feed, scans, setToken } = useSentinel();

const tokenInput = ref("");
function submitToken() {
  if (tokenInput.value.trim()) setToken(tokenInput.value);
  tokenInput.value = "";
}

/* ---------- Playground : tester la passerelle depuis le dashboard ---------- */
const scanText = ref(
  "Rédige une relance pour Jean Dupont concernant le virement vers FR7610107001011234567890129"
);
const scanKey = ref(localStorage.getItem("sentinel_api_key") || "");
const scanning = ref(false);
const scanResult = ref(null);
const scanError = ref("");

async function runScan() {
  if (!scanText.value.trim() || scanning.value) return;
  scanning.value = true;
  scanError.value = "";
  scanResult.value = null;
  localStorage.setItem("sentinel_api_key", scanKey.value.trim());
  try {
    const headers = { "Content-Type": "application/json" };
    if (scanKey.value.trim()) headers["X-SENTINEL-Key"] = scanKey.value.trim();
    const r = await fetch(`${API_BASE}/gateway/scan`, {
      method: "POST",
      headers,
      body: JSON.stringify({ text: scanText.value }),
    });
    if (r.status === 401) {
      scanError.value = "Clé SENTINEL requise ou invalide (champ ci-dessous).";
      return;
    }
    if (r.status === 429) {
      scanError.value = "Quota dépassé — réessayez dans une minute.";
      return;
    }
    scanResult.value = await r.json();
  } catch (_) {
    scanError.value = "Backend injoignable.";
  } finally {
    scanning.value = false;
  }
}

const DONUT_COLORS = ["#f59a23", "#ffbe45", "#ffd98a", "#dd820c", "#b96a05", "#8f5304"];

const PROVIDER_INFO = {
  groq:      { label: "Groq",      region: "US", sovereign: false },
  openai:    { label: "OpenAI",    region: "US", sovereign: false },
  anthropic: { label: "Anthropic", region: "US", sovereign: false },
  mistral:   { label: "Mistral",   region: "UE", sovereign: true },
  ollama:    { label: "Ollama",    region: "Local", sovereign: true },
};

const providerRows = computed(() => {
  const entries = Object.entries(stats.by_provider).sort((a, b) => b[1] - a[1]);
  const total = entries.reduce((s, [, c]) => s + c, 0) || 1;
  return entries.map(([key, count]) => {
    const info = PROVIDER_INFO[key] || { label: key, region: "?", sovereign: false };
    return { key, count, pct: (count / total) * 100, ...info };
  });
});

/* ---------- Donut : répartition par type ---------- */
const typeEntries = computed(() => {
  const entries = Object.entries(stats.by_type).sort((a, b) => b[1] - a[1]);
  const total = entries.reduce((s, [, c]) => s + c, 0) || 1;
  return entries.map(([type, count], i) => ({
    type, count,
    pct: (count / total) * 100,
    color: DONUT_COLORS[i % DONUT_COLORS.length],
  }));
});

const donutGradient = computed(() => {
  if (!typeEntries.value.length) return "conic-gradient(#e4e4e7 0 100%)";
  let acc = 0;
  const stops = typeEntries.value.map((e) => {
    const from = acc; acc += e.pct;
    return `${e.color} ${from}% ${acc}%`;
  });
  return `conic-gradient(${stops.join(", ")})`;
});

/* ---------- Tableau bas-droite : détail par type + sparkline ---------- */
function sparkPoints(type) {
  const now = Math.floor(Date.now() / 1000);
  const N = 20, vals = [];
  for (let i = N - 1; i >= 0; i--) {
    const start = now - (i + 1) * 90, end = now - i * 90;
    vals.push(feed.value.filter((e) => e.entity_type === type && e.ts >= start && e.ts < end).length);
  }
  const max = Math.max(1, ...vals);
  return vals.map((v, i) => `${(i / (N - 1)) * 100},${22 - (v / max) * 18}`).join(" ");
}

const typeRows = computed(() =>
  typeEntries.value.map((e) => {
    const rows = feed.value.filter((f) => f.entity_type === e.type);
    const blocked = rows.filter((f) => f.action !== "TOKENIZE").length;
    return { ...e, tokenized: e.count - Math.min(blocked, e.count), blocked, spark: sparkPoints(e.type) };
  })
);

/* ---------- Flux (tableau gauche) ---------- */
function labelAction(a) {
  if (a === "TOKENIZE") return "Anonymisé";
  if (a === "BLOCK") return "Bloqué";
  if (a === "BLOCK_REQUEST") return "Requête rejetée";
  return a;
}
function ts(t) {
  return new Date(t * 1000).toLocaleTimeString("fr-FR", { hour12: false });
}
</script>

<template>
  <div v-if="authRequired" class="auth-overlay">
    <div class="auth-card">
      <h1>SENTINEL</h1>
      <p>Ce dashboard est protégé. Saisissez le token d'accès<br />(<code>DASHBOARD_TOKEN</code> du serveur).</p>
      <form @submit.prevent="submitToken">
        <input
          v-model="tokenInput"
          type="password"
          placeholder="Token dashboard"
          autofocus
        />
        <button type="submit">Accéder</button>
      </form>
    </div>
  </div>

  <div v-else class="sheet">
    <div class="header">
      <div>
        <h1>SENTINEL</h1>
        <div class="sub">Surveillance temps réel des flux IA de l'entreprise</div>
      </div>
      <div class="header-right">
        <span>Documentation</span>
        <span>Audit</span>
        <span class="status">
          <span class="dot" :class="connected ? 'live' : 'down'"></span>
          {{ connected ? "Flux connecté" : "Reconnexion..." }}
        </span>
      </div>
    </div>

    <div class="toolbar">
      <div class="pills">
        <button class="pill active">Temps réel</button>
        <button class="pill">Conformité</button>
        <button class="pill">Corpus</button>
      </div>
      <div class="ranges">
        <button class="range">24 heures</button>
        <button class="range active">Session</button>
        <button class="range">7 jours</button>
        <button class="range">30 jours</button>
      </div>
    </div>

    <div class="panel playground">
      <h2>Tester la passerelle</h2>
      <textarea
        v-model="scanText"
        rows="3"
        placeholder="Collez un prompt contenant des données sensibles (IBAN, nom, clé API…)"
      ></textarea>
      <div class="playground-row">
        <input
          v-model="scanKey"
          type="password"
          placeholder="Clé SENTINEL (sntl_…) — optionnelle en mode démo"
        />
        <button @click="runScan" :disabled="scanning">
          {{ scanning ? "Analyse…" : "Analyser" }}
        </button>
      </div>
      <div v-if="scanError" class="playground-error">{{ scanError }}</div>
      <template v-if="scanResult">
        <div v-if="scanResult.blocked" class="playground-blocked">
          Requête bloquée — {{ scanResult.reason }}
          <span class="mono">({{ scanResult.audit_hash }})</span>
        </div>
        <template v-else>
          <div class="playground-label">
            Ce que le fournisseur d'IA aurait reçu :
          </div>
          <pre class="playground-output">{{ scanResult.sanitized }}</pre>
          <div v-if="scanResult.decisions && scanResult.decisions.length" class="playground-decisions">
            <span
              v-for="(d, i) in scanResult.decisions"
              :key="i"
              class="badge"
              :class="{ block: d.action !== 'TOKENIZE' }"
            >
              {{ d.type }} · {{ d.action === "TOKENIZE" ? "anonymisé" : "bloqué" }} · {{ d.layer }}
            </span>
          </div>
          <div v-else class="playground-label ok-note">
            Aucune donnée sensible détectée — le prompt part tel quel.
          </div>
        </template>
      </template>
    </div>

    <div class="grid-kpi">
      <div class="kpi">
        <div class="label">Prompts analysés</div>
        <div class="value">{{ stats.prompts_scanned }}</div>
        <div class="delta">Session en cours <span class="up">actif</span></div>
      </div>
      <div class="kpi">
        <div class="label">Données anonymisées</div>
        <div class="value">{{ stats.entities_tokenized }}</div>
        <div class="delta">Tokenisation FPE <span class="up">réversible</span></div>
      </div>
      <div class="kpi">
        <div class="label">Secrets bloqués</div>
        <div class="value">{{ stats.secrets_blocked }}</div>
        <div class="delta">Clés API, tokens <span class="up">jamais transmis</span></div>
      </div>
      <div class="kpi">
        <div class="label">Fuites IP bloquées</div>
        <div class="value">{{ stats.ip_leaks_blocked }}</div>
        <div class="delta">
          Documents confidentiels
          <span :class="stats.ip_leaks_blocked ? 'bad' : 'up'">
                       {{ stats.ip_leaks_blocked ? "interceptées" : "aucune" }}
          </span>
        </div>
      </div>
    </div>

    <div class="grid-mid">
      <div class="panel">
        <h2>Répartition des données interceptées</h2>
        <div v-if="typeEntries.length" class="donut-wrap">
          <div class="donut" :style="{ background: donutGradient }"></div>
          <div class="legend">
            <div v-for="e in typeEntries" :key="e.type" class="legend-row">
              <span class="legend-dot" :style="{ background: e.color }"></span>
              {{ e.type }}
              <span class="legend-val">{{ e.count }} ({{ e.pct.toFixed(1) }}%)</span>
            </div>
          </div>
        </div>
        <div v-else class="empty">Aucune donnée interceptée pour l'instant.</div>
        <div class="audit-line">
          <span class="dot" :class="auditIntegrity ? 'live' : 'down'"></span>
          Chaîne d'audit :
          <span :class="auditIntegrity ? 'ok' : 'ko'">
            {{ auditIntegrity ? "vérifiée, inviolée" : "COMPROMISE" }}
          </span>
        </div>
      </div>

      <div class="panel">
        <h2>Registre Shadow AI — fournisseurs appelés</h2>
        <table v-if="providerRows.length">
          <thead>
            <tr><th>Fournisseur</th><th>Région</th><th>Souveraineté</th><th>Requêtes</th><th>Part</th></tr>
          </thead>
          <tbody>
            <tr v-for="p in providerRows" :key="p.key">
              <td>{{ p.label }}</td>
              <td class="num">{{ p.region }}</td>
              <td>
                <span class="badge" :class="{ block: !p.sovereign }">
                  {{ p.sovereign ? "Conforme UE" : "Hors UE" }}
                </span>
              </td>
              <td class="num">{{ p.count }}</td>
              <td class="num">{{ p.pct.toFixed(1) }}%</td>
            </tr>
          </tbody>
        </table>
        <div v-else class="empty">
          Aucun appel fournisseur pour l'instant. Envoie un prompt via la passerelle.
        </div>
        <div class="audit-line">
          <span class="dot live"></span>
          Chaque appel sortant est tracé pour la conformité RGPD et AI Act.
        </div>
      </div>
    </div>

    <div class="grid-bottom">
      <div class="panel">
        <h2>Flux des décisions</h2>
        <table v-if="feed.length">
          <thead>
            <tr><th>Heure</th><th>Type</th><th>Action</th><th>Couche</th><th>Audit</th></tr>
          </thead>
          <tbody>
            <tr v-for="(e, i) in feed.slice(0, 9)" :key="i">
              <td class="num">{{ ts(e.ts) }}</td>
              <td><span class="badge">{{ e.entity_type }}</span></td>
              <td>
                <span class="badge" :class="{ block: e.action !== 'TOKENIZE' }">
                  {{ labelAction(e.action) }}
                </span>
              </td>
              <td><span class="badge layer">{{ e.layer }}</span></td>
              <td class="mono">{{ e.audit_hash }}</td>
            </tr>
          </tbody>
        </table>
        <div v-else class="empty">En attente de trafic sur la passerelle.</div>
      </div>

      <div class="panel">
        <h2>Détections par type de donnée</h2>
        <table v-if="typeRows.length">
          <thead>
            <tr>
              <th>Type</th><th>Anonymisées</th><th>Bloquées</th>
              <th>Part</th><th>Tendance</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in typeRows" :key="r.type">
              <td><span class="legend-dot" :style="{ background: r.color, display: 'inline-block', marginRight: '8px' }"></span>{{ r.type }}</td>
              <td class="orange-num">{{ r.tokenized }}</td>
              <td class="orange-num">{{ r.blocked }}</td>
              <td class="num">{{ r.pct.toFixed(1) }}%</td>
              <td>
                <svg class="spark" width="100" height="24" viewBox="0 0 100 24">
                  <polyline :points="r.spark" />
                </svg>
              </td>
            </tr>
            <tr class="total">
              <td>Total</td>
              <td class="num">{{ stats.entities_tokenized }}</td>
              <td class="num">{{ stats.secrets_blocked + stats.ip_leaks_blocked }}</td>
              <td class="num">100%</td>
              <td></td>
            </tr>
          </tbody>
        </table>
        <div v-else class="empty">Aucune détection pour l'instant.</div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.auth-overlay {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
}
.auth-card {
  text-align: center;
  padding: 40px 48px;
  border: 1px solid #e4e4e7;
  border-radius: 12px;
  background: #fff;
  box-shadow: 0 4px 24px rgba(0, 0, 0, 0.06);
}
.auth-card h1 { margin-bottom: 8px; }
.auth-card p { color: #71717a; font-size: 14px; margin-bottom: 20px; }
.auth-card form { display: flex; gap: 8px; justify-content: center; }
.auth-card input {
  padding: 10px 14px;
  border: 1px solid #d4d4d8;
  border-radius: 8px;
  font-size: 14px;
  width: 240px;
}
.auth-card button {
  padding: 10px 18px;
  border: none;
  border-radius: 8px;
  background: #f59a23;
  color: #fff;
  font-weight: 600;
  cursor: pointer;
}
.auth-card button:hover { background: #dd820c; }

/* ---------- Playground ---------- */
.playground { margin-bottom: 16px; }
.playground textarea {
  width: 100%;
  box-sizing: border-box;
  padding: 10px 12px;
  border: 1px solid #d4d4d8;
  border-radius: 8px;
  font: inherit;
  font-size: 14px;
  resize: vertical;
}
.playground-row { display: flex; gap: 8px; margin-top: 8px; }
.playground-row input {
  flex: 1;
  padding: 8px 12px;
  border: 1px solid #d4d4d8;
  border-radius: 8px;
  font-size: 13px;
}
.playground-row button {
  padding: 8px 20px;
  border: none;
  border-radius: 8px;
  background: #f59a23;
  color: #fff;
  font-weight: 600;
  cursor: pointer;
}
.playground-row button:hover { background: #dd820c; }
.playground-row button:disabled { opacity: 0.6; cursor: wait; }
.playground-error {
  margin-top: 10px; color: #b02a37; font-size: 14px;
}
.playground-blocked {
  margin-top: 10px;
  padding: 10px 12px;
  background: #fdecee;
  border: 1px solid #f1aeb5;
  border-radius: 8px;
  color: #b02a37;
  font-weight: 600;
  font-size: 14px;
}
.playground-label { margin-top: 12px; font-size: 13px; color: #71717a; }
.playground-label.ok-note { color: #157347; }
.playground-output {
  margin-top: 6px;
  padding: 10px 12px;
  background: #fafafa;
  border: 1px solid #e4e4e7;
  border-radius: 8px;
  font-size: 13px;
  white-space: pre-wrap;
  word-break: break-word;
}
.playground-decisions {
  margin-top: 8px; display: flex; gap: 6px; flex-wrap: wrap;
}
</style>
