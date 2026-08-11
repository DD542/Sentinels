"""
Metriques Prometheus — observabilite production.

Toutes les metriques sont enregistrees ici et alimentees depuis les
points de passage existants (events.publish, DetectionEngine.analyze,
ratelimit.check) : aucune instrumentation eparpillee dans le code metier.

Exposees sur GET /metrics (format texte Prometheus). L'endpoint est
concu pour un scrape sur reseau interne — a restreindre par le pare-feu
ou le reverse-proxy en production.
"""
from __future__ import annotations
from prometheus_client import (Counter, Gauge, Histogram, generate_latest,
                               CONTENT_TYPE_LATEST)

PROMPTS_SCANNED = Counter(
    "sentinel_prompts_scanned_total",
    "Nombre de prompts analyses par le moteur de detection")

DECISIONS = Counter(
    "sentinel_decisions_total",
    "Decisions prises par le pipeline (tokenisation, blocage...)",
    ["action", "entity_type", "layer"])

PROVIDER_REQUESTS = Counter(
    "sentinel_provider_requests_total",
    "Appels transmis aux fournisseurs IA amont",
    ["provider"])

EVASION_FLAGS = Counter(
    "sentinel_evasion_flags_total",
    "Tentatives d'ingenierie sociale contre la passerelle (drapeaux L0)")

POLICY_SUPPRESSED = Counter(
    "sentinel_policy_suppressed_total",
    "Detections ecartees par la politique du client (faux positifs regles)",
    ["reason"])

RATE_LIMITED = Counter(
    "sentinel_rate_limited_total",
    "Requetes rejetees en 429 (quota par client depasse)")

SCAN_DURATION = Histogram(
    "sentinel_scan_duration_seconds",
    "Duree d'analyse d'un prompt par le pipeline L0-L4",
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0))

AUDIT_CHAIN_ENTRIES = Gauge(
    "sentinel_audit_chain_entries",
    "Entrees dans la chaine d'audit HMAC")

VAULT_TOKENS = Gauge(
    "sentinel_vault_tokens",
    "Tokens FPE actifs dans le vault (valeurs reversibles)")


def _bind_gauges() -> None:
    """Les jauges lisent l'etat reel au moment du scrape (O(1))."""
    from .audit import chain
    from .vault import fpe
    AUDIT_CHAIN_ENTRIES.set_function(chain.count)
    VAULT_TOKENS.set_function(lambda: len(fpe._REVERSE_MAP))


_bind_gauges()


def record_event(event: dict) -> None:
    """Alimente les compteurs depuis un evenement events.publish."""
    kind = event.get("kind")
    if kind == "scan":
        PROMPTS_SCANNED.inc()
    elif kind == "provider":
        PROVIDER_REQUESTS.labels(provider=event.get("provider", "?")).inc()
    elif kind == "decision":
        action = event.get("action", "?")
        if action == "EVASION_FLAG":
            EVASION_FLAGS.inc()
            return
        DECISIONS.labels(
            action=action,
            entity_type=event.get("entity_type", "?"),
            layer=event.get("layer", "?"),
        ).inc()


def render() -> tuple[bytes, str]:
    """Corps + content-type de la reponse /metrics."""
    return generate_latest(), CONTENT_TYPE_LATEST
