from __future__ import annotations
import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .config import get_settings
from .detection.engine import DetectionEngine
from .detection.types import Action, EntityType
from .detection import l3_semantic
from .gateway.proxy import router as gateway_router
from .dashboard import router as dashboard_router
from .vault import fpe
from .audit import chain
from . import events

settings = get_settings()
app = FastAPI(title=settings.app_name)

# CORS : le front Vite (localhost:5173) doit pouvoir appeler l'API + WS.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(gateway_router)
app.include_router(dashboard_router)
engine = DetectionEngine()


class ScanRequest(BaseModel):
    text: str


class IngestRequest(BaseModel):
    doc_id: str
    text: str


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": settings.app_name}


@app.post("/corpus/ingest")
async def ingest(req: IngestRequest) -> dict:
    """Indexe un document confidentiel de l'entreprise."""
    result = await asyncio.to_thread(l3_semantic.ingest_document, req.doc_id, req.text)
    chain.append("CORPUS_INGEST", "DOCUMENT", req.doc_id,
                 {"shingles": result["shingles"], "chunks": result["chunks"]})
    return result


@app.get("/corpus/stats")
async def corpus_stats() -> dict:
    return l3_semantic.corpus_stats()


@app.post("/gateway/scan")
async def scan(req: ScanRequest) -> dict:
    """Scan seul (sans transmission) : utile pour tests et integration."""
    result = await engine.analyze(req.text)
    await events.publish({"kind": "scan", "length": len(req.text)})

    ip_leaks = [f for f in result.findings if f.entity_type == EntityType.IP_LEAK]
    if ip_leaks:
        leak = max(ip_leaks, key=lambda f: f.confidence)
        entry = chain.append(
            action="BLOCK_REQUEST",
            entity_type="IP_LEAK",
            entity_id=str(leak.meta.get("source_doc")
                          or ",".join(leak.meta.get("source_docs", ["?"]))),
            detail={"confidence": leak.confidence, **leak.meta},
        )
        await events.publish({
            "kind": "decision", "action": "BLOCK_REQUEST",
            "entity_type": "IP_LEAK", "layer": "L3",
            "confidence": round(leak.confidence, 3),
            "audit_hash": entry["hash"][:12],
        })
        return {
            "blocked": True,
            "reason": "Contenu confidentiel de l'entreprise detecte",
            "method": leak.meta.get("method"),
            "confidence": round(leak.confidence, 3),
            "audit_hash": entry["hash"][:12],
            "audit_integrity": chain.verify_integrity(),
        }

    sanitized = req.text
    decisions = []
    for f in sorted(result.findings, key=lambda x: x.start, reverse=True):
        action = engine.decide(f)
        if action == Action.BLOCK:
            sanitized = sanitized[:f.start] + "[BLOCKED]" + sanitized[f.end:]
        elif action == Action.TOKENIZE:
            token = fpe.tokenize(f.value, f.entity_type)
            sanitized = sanitized[:f.start] + token + sanitized[f.end:]

        entry = chain.append(
            action=action.value,
            entity_type=f.entity_type.value,
            entity_id=f"{f.entity_type.value}:{f.start}",
            detail={"value": f.value, "confidence": f.confidence, "layer": f.layer},
        )
        await events.publish({
            "kind": "decision", "action": action.value,
            "entity_type": f.entity_type.value, "layer": f.layer,
            "confidence": round(f.confidence, 3),
            "audit_hash": entry["hash"][:12],
        })
        decisions.append({
            "type": f.entity_type.value, "action": action.value,
            "layer": f.layer, "audit_hash": entry["hash"][:12],
        })

    return {
        "blocked": False,
        "original_length": len(req.text),
        "sanitized": sanitized,
        "decisions": decisions,
        "audit_integrity": chain.verify_integrity(),
    }