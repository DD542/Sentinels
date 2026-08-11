"""
Rapport de conformite — livrable destine au DPO / RSSI.

GET /compliance/report.json : etat canonique signe (HMAC-SHA256 avec la
cle d'audit). GET /compliance/report : le meme contenu en HTML autonome,
imprimable en PDF depuis le navigateur (Ctrl+P), pour joindre a un
dossier d'audit.

La signature couvre le JSON canonique (cles triees, sans le champ
"signature") : l'exploitant, seul detenteur de la cle d'audit, peut
re-verifier a tout moment qu'un rapport archive n'a pas ete altere.
"""
from __future__ import annotations
import hashlib
import hmac
import html
import json
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from .config import get_settings
from .dashboard import require_dashboard_token
from .audit import chain
from .audit import subjects as audit_subjects
from . import events
from . import db

settings = get_settings()
router = APIRouter()

# Meme referentiel de souverainete que le dashboard (registre Shadow AI)
PROVIDER_INFO = {
    "groq":      {"label": "Groq",      "region": "US",    "eu_sovereign": False},
    "openai":    {"label": "OpenAI",    "region": "US",    "eu_sovereign": False},
    "anthropic": {"label": "Anthropic", "region": "US",    "eu_sovereign": False},
    "mistral":   {"label": "Mistral",   "region": "UE",    "eu_sovereign": True},
    "ollama":    {"label": "Ollama",    "region": "Local", "eu_sovereign": True},
}


def _sign(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hmac.new(bytes.fromhex(settings.audit_hmac_key),
                    canonical.encode(), hashlib.sha256).hexdigest()


async def build_report() -> dict:
    stats = events.snapshot()["stats"]
    providers = []
    for key, count in sorted(stats.get("by_provider", {}).items(),
                             key=lambda kv: -kv[1]):
        info = PROVIDER_INFO.get(key, {"label": key, "region": "?",
                                       "eu_sovereign": False})
        providers.append({"provider": info["label"], "requests": count,
                          "region": info["region"],
                          "eu_sovereign": info["eu_sovereign"]})

    payload = {
        "report": "SENTINEL — rapport de conformite",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scope": ("depuis l'installation (compteurs persistes)"
                  if db.is_enabled()
                  else "session en cours (compteurs en memoire)"),
        "activity": {
            "prompts_scanned": stats["prompts_scanned"],
            "entities_tokenized": stats["entities_tokenized"],
            "secrets_blocked": stats["secrets_blocked"],
            "ip_leaks_blocked": stats["ip_leaks_blocked"],
            "requests_blocked": stats["requests_blocked"],
            "by_type": dict(stats.get("by_type", {})),
        },
        "shadow_ai_registry": providers,
        "audit_chain": {
            # Le rapport de conformite justifie une verification
            # COMPLETE : c'est precisement sa raison d'etre.
            "entries": chain.count(),
            "integrity_verified": await chain.verify_integrity_async(),
            "head_hash": chain.head() if chain.count() else None,
        },
        "security_posture": {
            "persistence_enabled": db.is_enabled(),
            "rate_limit_per_minute": settings.rate_limit_per_minute,
            "audit_retention_days": settings.audit_retention_days or None,
            "vault_ttl_hours": settings.vault_ttl_hours,
            "dashboard_auth_enabled": bool(settings.dashboard_token),
            "dedicated_admin_token": bool(settings.admin_token),
            "strict_mode": settings.strict_mode,
        },
    }
    payload["signature"] = _sign(payload)
    return payload


@router.get("/compliance/report.json",
            dependencies=[Depends(require_dashboard_token)])
async def report_json() -> dict:
    return await build_report()


class ForgetRequest(BaseModel):
    entity_id: str
    admin_token: str


@router.post("/compliance/forget")
async def forget_entity(req: ForgetRequest) -> dict:
    """Droit à l'effacement (RGPD art. 17) par crypto-shredding.

    Détruit la clé de chiffrement de l'entité `entity_id` : le détail de
    toutes ses entrées d'audit devient définitivement illisible, tandis
    que la chaîne de hachage reste intègre (on prouve qu'un traitement a
    eu lieu sans jamais pouvoir relire la donnée personnelle). L'effacement
    est lui-même scellé dans le journal. Protégé par le token admin."""
    if not secrets.compare_digest(req.admin_token,
                                  settings.effective_admin_token):
        raise HTTPException(status_code=403, detail="Token admin invalide")
    affected = await chain.forget_async(req.entity_id)
    # L'acte d'effacement est tracé (sous une entité distincte, non oubliée).
    entry = await chain.append_async(
        "ERASURE", "GDPR", f"erasure:{req.entity_id}",
        {"target": req.entity_id, "entries_shredded": affected})
    return {
        "entity_id": req.entity_id,
        "entries_shredded": affected,
        "method": "crypto-shredding (Fernet DEK détruite)",
        "audit_hash": entry["hash"][:12],
        "chain_integrity": chain.integrity_status()["verified"],
    }


class SubjectRequest(BaseModel):
    value: str          # nom, IBAN, email… de la personne concernée
    admin_token: str


@router.post("/compliance/subject")
async def subject_access(req: SubjectRequest) -> dict:
    """Droit d'accès (RGPD art. 15) : ce que le journal contient sur une
    personne, en **métadonnées** (nombre d'entrées, types, période).

    La valeur transmise sert uniquement à recalculer la référence
    aveugle : elle n'est ni stockée, ni journalisée, et la réponse ne
    renvoie aucune donnée déchiffrée."""
    if not secrets.compare_digest(req.admin_token,
                                  settings.effective_admin_token):
        raise HTTPException(status_code=403, detail="Token admin invalide")
    return await chain.subject_summary(req.value)


@router.post("/compliance/forget-subject")
async def forget_subject(req: SubjectRequest) -> dict:
    """Droit à l'effacement (RGPD art. 17) visant **une personne**.

    Détruit sa clé de chiffrement : toutes ses entrées deviennent
    illisibles, et uniquement les siennes. La chaîne de hachage reste
    intacte — la preuve qu'un traitement a eu lieu demeure. L'acte
    d'effacement est scellé dans le journal avec la référence aveugle,
    jamais l'identité en clair."""
    if not secrets.compare_digest(req.admin_token,
                                  settings.effective_admin_token):
        raise HTTPException(status_code=403, detail="Token admin invalide")

    ref = audit_subjects.subject_ref(req.value)
    if ref is None:
        raise HTTPException(status_code=400,
                            detail="Valeur vide ou sans contenu exploitable")
    affected = await chain.forget_subject(req.value)
    entry = await chain.append_async(
        "ERASURE_SUBJECT", "GDPR", f"erasure:{ref}",
        {"subject_ref": ref, "entries_shredded": affected})
    return {
        "subject_ref": ref,
        "entries_shredded": affected,
        "method": "crypto-shredding (cle de la personne detruite)",
        "audit_hash": entry["hash"][:12],
        "chain_integrity": chain.integrity_status()["verified"],
    }


def _yesno(v: bool) -> str:
    return "Oui" if v else "Non"


@router.get("/compliance/report", response_class=HTMLResponse,
            dependencies=[Depends(require_dashboard_token)])
async def report_html() -> HTMLResponse:
    r = await build_report()
    a, audit, posture = r["activity"], r["audit_chain"], r["security_posture"]

    type_rows = "".join(
        f"<tr><td>{html.escape(t)}</td><td class='n'>{c}</td></tr>"
        for t, c in sorted(a["by_type"].items(), key=lambda kv: -kv[1])
    ) or "<tr><td colspan='2'>Aucune détection sur la période.</td></tr>"

    provider_rows = "".join(
        f"<tr><td>{html.escape(p['provider'])}</td>"
        f"<td>{html.escape(p['region'])}</td>"
        f"<td>{'Conforme UE' if p['eu_sovereign'] else 'Hors UE'}</td>"
        f"<td class='n'>{p['requests']}</td></tr>"
        for p in r["shadow_ai_registry"]
    ) or "<tr><td colspan='4'>Aucun appel fournisseur sur la période.</td></tr>"

    integrity = audit["integrity_verified"]
    doc = f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<title>SENTINEL — Rapport de conformité</title>
<style>
  body {{ font-family: Georgia, serif; max-width: 800px; margin: 40px auto;
         color: #1a1a1a; line-height: 1.5; }}
  h1 {{ border-bottom: 3px solid #f59a23; padding-bottom: 8px; }}
  h2 {{ margin-top: 32px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 12px 0; }}
  th, td {{ border: 1px solid #ccc; padding: 6px 10px; text-align: left; }}
  th {{ background: #f5f5f5; }}
  td.n {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .ok {{ color: #157347; font-weight: bold; }}
  .ko {{ color: #b02a37; font-weight: bold; }}
  .sig {{ font-family: monospace; font-size: 12px; word-break: break-all;
          background: #f5f5f5; padding: 10px; }}
  .muted {{ color: #666; font-size: 14px; }}
  @media print {{ body {{ margin: 10mm; }} }}
</style></head><body>
<h1>SENTINEL — Rapport de conformité</h1>
<p class="muted">Généré le {html.escape(r["generated_at"])} ·
Périmètre : {html.escape(r["scope"])}</p>

<h2>1. Synthèse d'activité</h2>
<table>
<tr><th>Indicateur</th><th>Valeur</th></tr>
<tr><td>Prompts analysés</td><td class="n">{a["prompts_scanned"]}</td></tr>
<tr><td>Données personnelles pseudonymisées (FPE)</td><td class="n">{a["entities_tokenized"]}</td></tr>
<tr><td>Secrets bloqués</td><td class="n">{a["secrets_blocked"]}</td></tr>
<tr><td>Fuites de documents confidentiels bloquées</td><td class="n">{a["ip_leaks_blocked"]}</td></tr>
</table>

<h2>2. Détections par type de donnée</h2>
<table><tr><th>Type</th><th>Occurrences</th></tr>{type_rows}</table>

<h2>3. Registre Shadow AI — transferts par fournisseur</h2>
<p class="muted">Contribution au suivi des transferts hors UE (RGPD, chap. V).</p>
<table><tr><th>Fournisseur</th><th>Région</th><th>Souveraineté</th>
<th>Requêtes</th></tr>{provider_rows}</table>

<h2>4. Intégrité du journal d'audit</h2>
<table>
<tr><td>Entrées scellées (HMAC-SHA256 chaîné)</td><td class="n">{audit["entries"]}</td></tr>
<tr><td>Vérification de la chaîne</td>
<td class="{'ok' if integrity else 'ko'}">{'INTÈGRE' if integrity else 'COMPROMISE'}</td></tr>
<tr><td>Hash de tête</td><td class="sig">{html.escape(audit["head_hash"] or "—")}</td></tr>
</table>

<h2>5. Posture de sécurité</h2>
<table>
<tr><td>Persistance (journal et vault survivent aux redémarrages)</td>
<td>{_yesno(posture["persistence_enabled"])}</td></tr>
<tr><td>Rate-limiting par client (req/min)</td>
<td>{posture["rate_limit_per_minute"] or "désactivé"}</td></tr>
<tr><td>Dashboard et WebSocket authentifiés</td>
<td>{_yesno(posture["dashboard_auth_enabled"])}</td></tr>
<tr><td>Token admin dédié</td>
<td>{_yesno(posture["dedicated_admin_token"])}</td></tr>
<tr><td>Mode strict (fail-closed)</td>
<td>{_yesno(posture["strict_mode"])}</td></tr>
<tr><td>Conservation du journal d'audit</td>
<td>{(str(posture["audit_retention_days"]) + " jours")
     if posture["audit_retention_days"] else "illimitée"}</td></tr>
<tr><td>Durée de vie des jetons du vault</td>
<td>{posture["vault_ttl_hours"]} h</td></tr>
</table>
<p class="muted">Au-delà de la durée de conservation, les entrées du
journal sont conservées (la chaîne doit rester vérifiable — AI Act
art. 26(6)) mais leur clé de déchiffrement est détruite : la preuve
demeure, la donnée personnelle devient illisible.</p>

<h2>6. Signature du rapport</h2>
<p class="muted">HMAC-SHA256 du JSON canonique (clés triées, champ
« signature » exclu), calculé avec la clé d'audit connue du seul
exploitant. Re-vérifiable via <code>/compliance/report.json</code>.</p>
<div class="sig">{r["signature"]}</div>

<p class="muted" style="margin-top:32px">Ce rapport décrit l'activité
technique de la passerelle SENTINEL. Il contribue aux obligations de
traçabilité (AI Act, RGPD) mais ne constitue pas, à lui seul, une preuve
de conformité ni un avis juridique. Voir
<code>docs/conformite-ai-act.md</code>.</p>
</body></html>"""
    return HTMLResponse(doc)
