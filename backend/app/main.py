from __future__ import annotations
import asyncio
from fastapi import FastAPI
from pydantic import BaseModel

from .config import get_settings
from .detection.engine import DetectionEngine
from .detection.types import Action, EntityType
from .detection import l3_semantic
from .vault import fpe
from .audit import chain

settings = get_settings()
app = FastAPI(title=settings.app_name)
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
async def stats() -> dict:
    return l3_semantic.corpus_stats()


@app.post("/gateway/scan")
async def scan(req: ScanRequest) -> dict:
    result = await engine.analyze(req.text)

    # --- Fuite de propriété intellectuelle : blocage TOTAL du prompt ---
    ip_leaks = [f for f in result.findings if f.entity_type == EntityType.IP_LEAK]
    if ip_leaks:
        leak = max(ip_leaks, key=lambda f: f.confidence)
        entry = chain.append(
            action="BLOCK_REQUEST",
            entity_type="IP_LEAK",
            entity_id=leak.meta.get("source_doc")
                      or ",".join(leak.meta.get("source_docs", ["?"])),
            detail={"confidence": leak.confidence, **leak.meta},
        )
        return {
            "blocked": True,
            "reason": "Contenu confidentiel de l'entreprise détecté",
            "method": leak.meta.get("method"),
            "confidence": round(leak.confidence, 3),
            "audit_hash": entry["hash"][:12],
            "audit_integrity": chain.verify_integrity(),
        }

    # --- Sinon : tokenisation / blocage ciblé, prompt transmissible ---
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