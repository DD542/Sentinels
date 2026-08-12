from __future__ import annotations
import asyncio
import os
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .config import get_settings
from .detection.engine import DetectionEngine, IDENTIFYING_TYPES
from .detection.types import Action, EntityType
from .detection import l3_semantic
from .detection import l2_ner
from .gateway.proxy import router as gateway_router
from .dashboard import router as dashboard_router
from .gateway.openai_compat import router as openai_router
from .compliance import router as compliance_router
from .sso import router as sso_router
from .vault import fpe
from .audit import chain
from . import events
from . import db
from . import auth
from . import metrics
from . import logs
from . import maintenance
from . import revocation
from . import policy
from . import rbac

settings = get_settings()


def enforce_strict_mode() -> None:
    """Fail-closed : en mode strict (production), on refuse de demarrer
    avec une posture incomplete plutot que de tourner degrade en silence."""
    problems = []
    if not settings.database_url:
        problems.append("database_url absent (persistance obligatoire)")
    if settings.vault_master_key == "0" * 64:
        problems.append("vault_master_key est la valeur par defaut")
    if settings.audit_hmac_key == "1" * 64:
        problems.append("audit_hmac_key est la valeur par defaut")
    if not settings.admin_token:
        problems.append("admin_token non defini")
    if not settings.dashboard_token:
        problems.append("dashboard_token non defini")
    if not settings.cors_origins:
        problems.append(
            "cors_origins non defini (le defaut n'autorise que localhost : "
            "la console serait injoignable depuis votre domaine)")
    else:
        try:
            settings.effective_cors_origins
        except ValueError as e:
            problems.append(str(e))
    if problems:
        raise RuntimeError(
            "SENTINEL_STRICT : demarrage refuse — " + " ; ".join(problems))


def _borner_les_fils_de_detection() -> None:
    """Borne le pool de fils utilisé par la détection.

    `asyncio.to_thread` s'appuie sur l'exécuteur par défaut, dont la
    taille suit le nombre de requêtes. Or la détection est un travail
    **CPU** (spaCy, Presidio) : au-delà du nombre de cœurs, les fils se
    disputent le GIL et le débit s'effondre au lieu de plafonner. Un
    pool borné fait la seule chose souhaitable — mettre en file plutôt
    que thrasher."""
    workers = settings.detection_workers or (os.cpu_count() or 4)
    asyncio.get_running_loop().set_default_executor(
        ThreadPoolExecutor(max_workers=workers,
                           thread_name_prefix="sentinel-detection"))
    logs.get_logger("main").info("pool de detection borne", extra={
        "event": "detection_pool", "workers": workers})


@asynccontextmanager
async def lifespan(app: FastAPI):
    logs.configure()
    _borner_les_fils_de_detection()
    if settings.strict_mode:
        enforce_strict_mode()
    await db.init_db()
    await auth.load_keys_from_db()
    await chain.load_from_db()
    await events.load_stats_from_db()
    await l3_semantic.load_corpus_from_db()
    await revocation.load_from_db()
    await policy.load_from_db()
    # Une verification complete au demarrage : c'est le seul moment ou
    # relire tout le journal a du sens. Ensuite, l'incrementale suffit.
    await chain.verify_integrity_async()
    if settings.strict_mode and not db.is_enabled():
        raise RuntimeError(
            "SENTINEL_STRICT : demarrage refuse — connexion Postgres impossible")
    await maintenance.run_once()
    maintenance.start()
    yield
    await maintenance.stop()
    await db.close_db()


app = FastAPI(title=settings.app_name, lifespan=lifespan)

# Origines configurables : sans ça, déployer la console sur un vrai
# domaine imposait d'éditer le code source. La liste reste EXPLICITE —
# jamais `*` : la console s'authentifie par cookie, et une origine joker
# laisserait n'importe quel site piloter la session d'un administrateur.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.effective_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(gateway_router)
app.include_router(dashboard_router)
app.include_router(openai_router)
app.include_router(compliance_router)
app.include_router(sso_router)
engine = DetectionEngine()


class ScanRequest(BaseModel):
    text: str


class IngestRequest(BaseModel):
    doc_id: str
    text: str


class KeyRequest(BaseModel):
    client_id: str
    admin_token: str


class RevokeRequest(BaseModel):
    client_id: str
    admin_token: str


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": settings.app_name,
            "persistence": db.is_enabled()}


@app.get("/metrics")
async def prometheus_metrics() -> Response:
    """Metriques Prometheus (format texte). Concu pour un scrape interne :
    a restreindre par pare-feu ou reverse-proxy en production."""
    body, content_type = metrics.render()
    return Response(content=body, media_type=content_type)


@app.post("/admin/keys")
async def create_key(req: KeyRequest, request: Request) -> dict:
    """Crée une clé API client. Protégé par le token admin dédié
    (ADMIN_TOKEN du .env ; repli sur la clé HMAC d'audit si absent)."""
    rbac.authorize_body_token(request, req.admin_token, rbac.KEYS_MANAGE)
    raw_key = await auth.generate_key_async(req.client_id)
    return {
        "client_id": req.client_id,
        "api_key": raw_key,
        "warning": "Cette cle ne sera affichee qu'une seule fois. Conservez-la.",
    }


@app.post("/admin/keys/revoke")
async def revoke_keys(req: RevokeRequest, request: Request) -> dict:
    """Revoque toutes les cles d'un client (cle compromise, fin de contrat).
    Effet immediat : la prochaine requete du client est rejetee en 401.
    La revocation est scellee dans la chaine d'audit."""
    rbac.authorize_body_token(request, req.admin_token, rbac.KEYS_MANAGE)
    count = await auth.revoke_client(req.client_id)
    if count == 0:
        raise HTTPException(status_code=404,
                            detail="Aucune cle active pour ce client")
    entry = await chain.append_async("KEY_REVOKED", "ADMIN", req.client_id,
                                     {"keys_revoked": count})
    return {"client_id": req.client_id, "keys_revoked": count,
            "audit_hash": entry["hash"][:12]}


@app.get("/admin/usage")
async def usage(request: Request,
                x_admin_token: str | None = Header(default=None),
                days: int = 30) -> dict:
    """Consommation par client (prompts, tokenisations, blocages) —
    base de facturation a l'usage. Protege par le token admin.
    Avec persistance : totaux lus en DB (source de verite, survit aux
    redemarrages) + ventilation journaliere sur `days` jours."""
    rbac.authorize_body_token(request, x_admin_token or "", rbac.USAGE_READ)

    if db.is_enabled():
        try:
            async with db.pool().acquire() as con:
                totals = await con.fetch(
                    "SELECT client_id, SUM(prompts) AS p, SUM(tokenized) AS t, "
                    "SUM(blocked) AS b FROM usage_counters GROUP BY client_id")
                daily = await con.fetch(
                    "SELECT client_id, day, prompts, tokenized, blocked "
                    "FROM usage_counters "
                    "WHERE day > CURRENT_DATE - $1::int "
                    "ORDER BY day DESC, client_id", days)
            clients = {r["client_id"]: {"prompts": int(r["p"]),
                                        "tokenized": int(r["t"]),
                                        "blocked": int(r["b"])}
                       for r in totals}
            return {
                "persistent": True,
                "clients": clients,
                "total_prompts": sum(c["prompts"] for c in clients.values()),
                "daily": [{"client_id": r["client_id"],
                           "day": r["day"].isoformat(),
                           "prompts": int(r["prompts"]),
                           "tokenized": int(r["tokenized"]),
                           "blocked": int(r["blocked"])} for r in daily],
            }
        except Exception:
            pass  # repli memoire

    by_client = events.snapshot()["stats"]["by_client"]
    return {"persistent": False, "clients": by_client,
            "total_prompts": sum(c["prompts"] for c in by_client.values())}


@app.get("/admin/audit/verify")
async def verify_audit(request: Request,
                       x_admin_token: str | None = Header(default=None),
                       full: bool = True) -> dict:
    """Vérifie le journal à la demande.

    `full=true` (défaut) relit toute la chaîne depuis la genèse : c'est
    la seule vérification qui détecte une altération ancienne, et son
    coût est proportionnel à l'historique. `full=false` ne contrôle que
    les entrées ajoutées depuis le dernier point de contrôle."""
    rbac.authorize_body_token(request, x_admin_token or "",
                              rbac.AUDIT_VERIFY)
    debut = time.perf_counter()
    if full:
        verifie = await chain.verify_integrity_async()
        controle = {"verified": verifie, "checked": chain.count(),
                    "scope": "complete"}
    else:
        controle = await chain.verify_incremental()
    return {**controle,
            "duration_ms": round((time.perf_counter() - debut) * 1000, 1),
            "entries": chain.count(),
            "head_hash": chain.head() if chain.count() else None}


@app.post("/admin/maintenance/purge")
async def trigger_purge(request: Request,
                        x_admin_token: str | None = Header(default=None)) -> dict:
    """Déclenche une passe de purge à la demande (la même tourne
    périodiquement) : tokens du vault expirés supprimés, clés d'audit
    hors rétention détruites. Les entrées d'audit, elles, ne sont jamais
    supprimées — la chaîne doit rester vérifiable."""
    rbac.authorize_body_token(request, x_admin_token or "",
                              rbac.MAINTENANCE_RUN)
    result = await maintenance.run_once()
    return {
        **result,
        "audit_retention_days": settings.audit_retention_days or "illimitee",
        "vault_ttl_hours": settings.vault_ttl_hours,
        "chain_integrity": await chain.verify_integrity_async(),
    }


class PolicyRequest(BaseModel):
    allowlist: list[str] = []
    min_confidence: dict[str, float] = {}
    actions: dict[str, str] = {}
    deep_scan: bool = False


@app.get("/audit/export")
async def export_audit(client_id: str = Depends(auth.verify_key),
                       limit: int = 5000) -> dict:
    """Journal d'audit **du client authentifié**, exportable.

    C'est ce que le cloisonnement rend possible : tant que toutes les
    entrées etaient chaînées ensemble, exporter le journal d'un client
    aurait revele l'existence de celles des autres.

    Le detail reste chiffre — les cles appartiennent a l'exploitant. Le
    client verifie donc le CHAINAGE (aucune entree retiree ni
    reordonnee), pas les sceaux HMAC."""
    return await chain.export_tenant(client_id, limit=min(limit, 20000))


@app.get("/policy")
async def read_policy(client_id: str = Depends(auth.verify_key)) -> dict:
    """Politique de detection du client authentifie."""
    politique = policy.get(client_id)
    return {"client_id": client_id, **politique,
            "degradations": policy.degradations(politique)}


@app.put("/policy")
async def write_policy(req: PolicyRequest,
                       client_id: str = Depends(auth.verify_key)) -> dict:
    """Remplace la politique du client : exceptions, seuils, actions.

    Regler sa detection est legitime — un faux positif repete pousse les
    employes a contourner l'outil, et une protection contournee ne
    protege rien. Mais un reglage peut aussi affaiblir un controle de
    securite : le changement est donc **scelle dans le journal d'audit**,
    et les degradations sont signalees dans le rapport de conformite."""
    try:
        applique = await policy.set_policy(client_id, req.model_dump())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    degradations = policy.degradations(applique)
    entry = await chain.append_async(
        "POLICY_UPDATE", "POLICY", f"policy:{client_id}",
        {"client": client_id, "policy": applique,
         "degradations": degradations}, tenant=client_id)
    return {"client_id": client_id, **applique,
            "degradations": degradations,
            "audit_hash": entry["hash"][:12]}


@app.post("/corpus/ingest")
async def ingest(req: IngestRequest,
                 client_id: str = Depends(auth.verify_key)) -> dict:
    """Indexe un document dans le corpus DU CLIENT authentifié
    (isolation multi-tenant)."""
    result = await asyncio.to_thread(l3_semantic.ingest_document,
                                     req.doc_id, req.text, client_id)
    # Persisté : sinon la protection disparaîtrait au redémarrage.
    result["persisted"] = await l3_semantic.persist_document(
        req.doc_id, client_id) > 0
    await chain.append_async("CORPUS_INGEST", "DOCUMENT", req.doc_id,
                             {"shingles": result["shingles"], "chunks": result["chunks"],
                              "client": client_id}, tenant=client_id)
    return result


@app.delete("/corpus/{doc_id}")
async def remove_document(doc_id: str,
                          client_id: str = Depends(auth.verify_key)) -> dict:
    """Retire un document du corpus du client (mémoire et base) : son
    contenu n'est plus protégé contre la fuite. Scellé dans l'audit."""
    removed = await l3_semantic.forget_document(doc_id, client_id)
    if removed == 0:
        raise HTTPException(status_code=404,
                            detail="Document inconnu dans votre corpus")
    entry = await chain.append_async("CORPUS_REMOVE", "DOCUMENT", doc_id,
                                     {"shingles_removed": removed,
                                      "client": client_id}, tenant=client_id)
    return {"doc_id": doc_id, "shingles_removed": removed,
            "audit_hash": entry["hash"][:12]}


@app.get("/corpus/stats")
async def corpus_stats(client_id: str = Depends(auth.verify_key)) -> dict:
    """Statistiques du corpus du client authentifié uniquement."""
    return l3_semantic.corpus_stats(client_id)


@app.post("/gateway/scan")
async def scan(req: ScanRequest,
               client_id: str = Depends(auth.verify_key)) -> dict:
    """Scan seul (sans transmission). Protégé par clé SENTINEL."""
    result = await engine.analyze(req.text, client_id)
    detected_language = l2_ner.detect_language(req.text)
    await events.publish({"kind": "scan", "length": len(req.text),
                          "client": client_id})

    evasion_flag = None
    if result.evasion_attempts:
        entry = await chain.append_async("EVASION_ATTEMPT", "GATEWAY", client_id,
                                         {"patterns": result.evasion_attempts},
                                         tenant=client_id)
        evasion_flag = entry["hash"][:12]
        await events.publish({
            "kind": "decision", "client": client_id, "action": "EVASION_FLAG",
            "entity_type": "EVASION", "layer": "L0",
            "confidence": 1.0, "audit_hash": evasion_flag,
        })

    ip_leaks = [f for f in result.findings if f.entity_type == EntityType.IP_LEAK]
    if ip_leaks:
        leak = max(ip_leaks, key=lambda f: f.confidence)
        entry = await chain.append_async(
            "BLOCK_REQUEST", "IP_LEAK",
            str(leak.meta.get("source_doc")
                or ",".join(leak.meta.get("source_docs", ["?"]))),
            {"confidence": leak.confidence, **leak.meta}, tenant=client_id)
        await events.publish({
            "kind": "decision", "client": client_id, "action": "BLOCK_REQUEST",
            "entity_type": "IP_LEAK", "layer": "L3",
            "confidence": round(leak.confidence, 3),
            "audit_hash": entry["hash"][:12],
        })
        return {
            "blocked": True,
            "reason": "Contenu confidentiel de l'entreprise detecte",
            "method": leak.meta.get("method"),
            "confidence": round(leak.confidence, 3),
            "language": detected_language,
            "evasion_flag": evasion_flag,
            "audit_hash": entry["hash"][:12],
            "audit_integrity": chain.integrity_status()["verified"],
        }

    sanitized = req.text
    decisions = []
    positional = [f for f in result.findings if "obfuscation" not in f.meta]
    by_value = [f for f in result.findings if "obfuscation" in f.meta]

    for f in sorted(positional, key=lambda x: x.start, reverse=True):
        action = engine.decide(f, client_id)
        if action == Action.BLOCK:
            sanitized = sanitized[:f.start] + "[BLOCKED]" + sanitized[f.end:]
        elif action == Action.TOKENIZE:
            token = await fpe.tokenize_async(f.value, f.entity_type, client_id)
            sanitized = sanitized[:f.start] + token + sanitized[f.end:]

        entry = await chain.append_async(
            action.value, f.entity_type.value,
            f"{f.entity_type.value}:{f.start}",
            {"value": f.value, "confidence": f.confidence, "layer": f.layer},
            # Indexe la personne concernée (index aveugle) pour les
            # seules données identifiantes : un secret technique ou une
            # fuite documentaire ne concerne aucun individu.
            subject=f.value if f.entity_type in IDENTIFYING_TYPES else None,
            tenant=client_id)
        await events.publish({
            "kind": "decision", "client": client_id, "action": action.value,
            "entity_type": f.entity_type.value, "layer": f.layer,
            "confidence": round(f.confidence, 3),
            "audit_hash": entry["hash"][:12],
        })
        decisions.append({
            "type": f.entity_type.value, "action": action.value,
            "layer": f.layer, "audit_hash": entry["hash"][:12],
        })

    for f in by_value:
        entry = await chain.append_async(
            "BLOCK", f.entity_type.value, f"{f.entity_type.value}:obf",
            {"confidence": f.confidence, "layer": f.layer,
             "obfuscation": f.meta.get("obfuscation")}, tenant=client_id)
        await events.publish({
            "kind": "decision", "client": client_id, "action": "BLOCK",
            "entity_type": f.entity_type.value, "layer": f.layer,
            "confidence": round(f.confidence, 3),
            "audit_hash": entry["hash"][:12],
        })
        decisions.append({
            "type": f.entity_type.value, "action": "BLOCK",
            "layer": f.layer, "obfuscation": f.meta.get("obfuscation"),
            "audit_hash": entry["hash"][:12],
        })
    if by_value:
        sanitized += "\n[Contenu dissimulé détecté et retiré par SENTINEL]"

    return {
        "blocked": False,
        "original_length": len(req.text),
        "sanitized": sanitized,
        "decisions": decisions,
        "language": detected_language,
        "evasion_flag": evasion_flag,
        "audit_integrity": chain.integrity_status()["verified"],
    }