"""
Test de charge de la passerelle — chiffres reproductibles.

Ce que ce script mesure : la latence de bout en bout (HTTP) de
`/gateway/scan`, sous concurrence, **par paliers**, pendant que le
journal d'audit grossit. C'est la mesure qui compte : elle dit si la
latence DERIVE avec l'historique, ce qui etait le defaut fatal avant la
verification a cout constant.

Ce que ce script NE mesure PAS, et il faut le dire :
  * pas d'appel aux fournisseurs d'IA — leur latence n'est pas la notre ;
  * une seule machine, un seul process (pas de repliques) ;
  * le rate-limiting est desactive, sinon il plafonnerait le test.

Usage :
    python tests/loadtest.py                        # memoire, 2000 req
    python tests/loadtest.py --db                   # avec Postgres
    python tests/loadtest.py --requests 10000 --concurrency 32
    python tests/loadtest.py --json                 # sortie machine
"""
from __future__ import annotations
import argparse
import asyncio
import json
import statistics
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import httpx  # noqa: E402

PORT = 8077

# Melange realiste : la majorite des prompts d'entreprise ne contiennent
# aucune donnee sensible ; mesurer uniquement le pire cas mentirait dans
# l'autre sens.
PROMPTS = [
    "Peux-tu resumer ce compte rendu de reunion en cinq points ?",
    "Redige une relance polie pour une facture en retard.",
    "Traduis ce paragraphe en anglais professionnel.",
    "Explique la difference entre un CDD et un CDI.",
    "Virement de 4200 euros vers FR7610107001011234567890129 pour Jean Dupont",
    "Contacte Marie Curie au 06 12 34 56 78 avant vendredi",
    "La cle est sk-abc123def456ghi789jkl012mno345pqrs, ne la partage pas",
    "Prepare un ordre du jour pour le comite de direction de mardi.",
]


def _demarrer_serveur(avec_db: bool) -> None:
    import uvicorn
    from app.config import get_settings
    s = get_settings()
    s.rate_limit_per_minute = 0        # sinon le test se plafonne lui-meme
    s.log_format = "text"
    if not avec_db:
        s.database_url = ""
        from app import db
        db._ENABLED = False
    from app.main import app
    threading.Thread(
        target=lambda: uvicorn.run(app, host="127.0.0.1", port=PORT,
                                   log_level="error"),
        daemon=True).start()


async def _attendre_le_serveur(timeout: float = 90.0) -> None:
    debut = time.time()
    async with httpx.AsyncClient(timeout=5.0) as c:
        while time.time() - debut < timeout:
            try:
                if (await c.get(f"http://127.0.0.1:{PORT}/health")).status_code == 200:
                    return
            except Exception:
                pass
            await asyncio.sleep(0.5)
    raise RuntimeError("le serveur n'a pas demarre")


async def _cle_client() -> str:
    from app.config import get_settings
    async with httpx.AsyncClient(timeout=30.0) as c:
        r = await c.post(f"http://127.0.0.1:{PORT}/admin/keys", json={
            "client_id": "loadtest",
            "admin_token": get_settings().effective_admin_token})
        return r.json()["api_key"]


async def _palier(cle: str, nb: int, concurrence: int) -> list[float]:
    """Envoie `nb` requetes avec `concurrence` en vol ; renvoie les
    latences en millisecondes."""
    latences: list[float] = []
    semaphore = asyncio.Semaphore(concurrence)
    entetes = {"X-SENTINEL-Key": cle}

    async with httpx.AsyncClient(timeout=120.0,
                                 limits=httpx.Limits(max_connections=concurrence * 2)) as c:
        async def une(i: int) -> None:
            async with semaphore:
                t0 = time.perf_counter()
                try:
                    r = await c.post(f"http://127.0.0.1:{PORT}/gateway/scan",
                                     headers=entetes,
                                     json={"text": PROMPTS[i % len(PROMPTS)]})
                    if r.status_code != 200:
                        return
                except Exception:
                    return
                latences.append((time.perf_counter() - t0) * 1000)

        await asyncio.gather(*(une(i) for i in range(nb)))
    return latences


def _percentiles(valeurs: list[float]) -> dict:
    v = sorted(valeurs)
    if not v:
        return {}
    def p(q: float) -> float:
        return v[min(len(v) - 1, int(len(v) * q))]
    return {"n": len(v), "p50": p(0.50), "p95": p(0.95), "p99": p(0.99),
            "moyenne": statistics.fmean(v), "max": v[-1]}


def _preremplir(n: int) -> None:
    """Grossit le journal AVANT la mesure. C'est le test direct de
    l'invariance : si la latence est la meme avec 0 et avec 50 000
    entrees, la verification a cout constant tient."""
    from app.audit import chain
    for i in range(n):
        chain.append("TOKENIZE", "PERSON", f"PRE:{i}",
                     {"value": "Jean Dupont"}, subject="Jean Dupont")


async def executer(nb_total: int, concurrence: int, paliers: int,
                   avec_db: bool, prefill: int = 0) -> dict:
    from app.audit import chain

    if prefill:
        t0 = time.perf_counter()
        _preremplir(prefill)
        print(f"  journal pre-rempli : {chain.count():,} entrees "
              f"({time.perf_counter()-t0:.1f} s)", file=sys.stderr)

    _demarrer_serveur(avec_db)
    await _attendre_le_serveur()
    cle = await _cle_client()

    # Prechauffage : le premier scan charge le modele de langue. L'inclure
    # dans les mesures ferait mentir la p99.
    await _palier(cle, 20, 4)

    par_palier = max(1, nb_total // paliers)
    resultats = []
    depart = time.perf_counter()
    for i in range(paliers):
        entrees_avant = chain.count()
        t0 = time.perf_counter()
        lat = await _palier(cle, par_palier, concurrence)
        duree = time.perf_counter() - t0
        stats = _percentiles(lat)
        resultats.append({
            "palier": i + 1,
            "entrees_journal_avant": entrees_avant,
            "entrees_journal_apres": chain.count(),
            "debit_req_s": len(lat) / duree if duree else 0,
            **stats,
        })
        print(f"  palier {i+1}/{paliers} — journal {chain.count():>7,} entrees — "
              f"p50 {stats['p50']:>6.0f} ms  p95 {stats['p95']:>6.0f} ms  "
              f"{len(lat)/duree:>6.1f} req/s", file=sys.stderr)

    duree_totale = time.perf_counter() - depart
    toutes = [l for r in resultats for l in [r["p50"]]]  # repere seulement
    return {
        "mode": "postgres" if avec_db else "memoire",
        "requetes": nb_total, "concurrence": concurrence,
        "prefill": prefill,
        "duree_s": round(duree_totale, 1),
        "entrees_journal_final": chain.count(),
        "paliers": resultats,
        "derive_p95": (resultats[-1]["p95"] / resultats[0]["p95"]
                       if resultats and resultats[0]["p95"] else None),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--requests", type=int, default=2000)
    ap.add_argument("--concurrency", type=int, default=16)
    ap.add_argument("--stages", type=int, default=5)
    ap.add_argument("--db", action="store_true", help="avec Postgres")
    ap.add_argument("--prefill", type=int, default=0,
                    help="entrees d'audit ajoutees AVANT la mesure")
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args()

    print(f"Charge : {args.requests} requetes, concurrence {args.concurrency}, "
          f"mode {'postgres' if args.db else 'memoire'}\n", file=sys.stderr)
    res = asyncio.run(executer(args.requests, args.concurrency,
                               args.stages, args.db, args.prefill))

    if args.as_json:
        print(json.dumps(res, indent=2))
        return

    print("\n" + "=" * 78)
    print(f" Mode {res['mode']} — {res['requetes']} requetes, "
          f"concurrence {res['concurrency'] if 'concurrency' in res else args.concurrency}")
    print("=" * 78)
    print(f" {'palier':>6} | {'journal':>9} | {'p50':>8} | {'p95':>8} | "
          f"{'p99':>8} | {'req/s':>7}")
    print("-" * 78)
    for r in res["paliers"]:
        print(f" {r['palier']:>6} | {r['entrees_journal_apres']:>9,} | "
              f"{r['p50']:>6.0f}ms | {r['p95']:>6.0f}ms | {r['p99']:>6.0f}ms | "
              f"{r['debit_req_s']:>7.1f}")
    print("-" * 78)
    if res["derive_p95"]:
        print(f" Derive p95 du premier au dernier palier : "
              f"x{res['derive_p95']:.2f}")
        print(" (proche de 1 = la latence NE DERIVE PAS avec la taille du journal)")
    print(f" Journal final : {res['entrees_journal_final']:,} entrees — "
          f"duree {res['duree_s']} s")


if __name__ == "__main__":
    main()
