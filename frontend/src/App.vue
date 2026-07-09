<script setup>
import { computed } from "vue";
import { useSentinel } from "./composables/useSentinel";

const { connected, auditIntegrity, stats, feed } = useSentinel();

const typeEntries = computed(() => {
  const entries = Object.entries(stats.by_type);
  entries.sort((a, b) => b[1] - a[1]);
  const max = entries.length ? entries[0][1] : 1;
  return entries.map(([type, count]) => ({ type, count, pct: (count / max) * 100 }));
});

function actionClass(a) { return (a || "").toLowerCase(); }
function labelAction(a) {
  if (a === "TOKENIZE") return "Anonymisé";
  if (a === "BLOCK") return "Bloqué";
  if (a === "BLOCK_REQUEST") return "Requête bloquée";
  return a;
}
function ts(t) {
  const d = new Date(t * 1000);
  return d.toLocaleTimeString("fr-FR", { hour12: false });
}
</script>

<template>
  <div class="header">
    <div class="brand">
      <h1>SENTINEL</h1>
      <span class="sub">Passerelle de sécurité IA — surveillance temps réel</span>
    </div>
    <div class="status">
      <span class="dot" :class="connected ? 'live' : 'down'"></span>
      {{ connected ? "Flux connecté" : "Reconnexion..." }}
    </div>
  </div>

  <div class="grid-kpi">
    <div class="kpi">
      <div class="label">Prompts analysés</div>
      <div class="value">{{ stats.prompts_scanned }}</div>
    </div>
    <div class="kpi ok">
      <div class="label">Données anonymisées</div>
      <div class="value">{{ stats.entities_tokenized }}</div>
    </div>
    <div class="kpi warn">
      <div class="label">Secrets bloqués</div>
      <div class="value">{{ stats.secrets_blocked }}</div>
    </div>
    <div class="kpi danger">
      <div class="label">Fuites IP bloquées</div>
      <div class="value">{{ stats.ip_leaks_blocked }}</div>
    </div>
    <div class="kpi">
      <div class="label">Requêtes rejetées</div>
      <div class="value">{{ stats.requests_blocked }}</div>
    </div>
  </div>

  <div class="grid-main">
    <div class="panel">
      <h2>Flux des décisions</h2>
      <div v-if="feed.length" class="feed">
        <div
          v-for="(e, i) in feed" :key="i"
          class="feed-row" :class="actionClass(e.action)"
        >
          <span class="tag">{{ e.entity_type }}</span>
          <span>
            <span class="action" :class="actionClass(e.action)">{{ labelAction(e.action) }}</span>
            <span class="tag layer" style="margin-left: 8px">{{ e.layer }}</span>
          </span>
          <span class="hash">{{ e.audit_hash }}</span>
        </div>
      </div>
      <div v-else class="empty">
        En attente de trafic. Envoie un prompt via /gateway/chat pour voir le flux.
      </div>
    </div>

    <div class="panel">
      <h2>Répartition par type de donnée</h2>
      <div v-if="typeEntries.length" class="bars">
        <div v-for="item in typeEntries" :key="item.type" class="bar-row">
          <span class="bar-label">{{ item.type }}</span>
          <div class="bar-track"><div class="bar-fill" :style="{ width: item.pct + '%' }"></div></div>
          <span class="bar-val">{{ item.count }}</span>
        </div>
      </div>
      <div v-else class="empty">Aucune donnée interceptée pour l'instant.</div>

      <h2 style="margin-top: 28px">Intégrité de l'audit</h2>
      <div class="audit-badge" :class="auditIntegrity ? 'ok' : 'broken'">
        <span class="dot" :class="auditIntegrity ? 'live' : 'down'"></span>
        {{ auditIntegrity ? "Chaîne de hachés vérifiée — inviolée" : "ALERTE : chaîne compromise" }}
      </div>
    </div>
  </div>
</template>