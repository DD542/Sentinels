"""
Benchmark EXTERNE — evaluation sur un jeu de donnees public non ecrit
par nous : ai4privacy/pii-masking-300k, sous-ensemble francais du split
validation (~8 400 lignes annotees en spans exacts).

Contrairement au benchmark interne (benchmark.py, 89 prompts maison),
celui-ci mesure la tenue du pipeline sur du texte tiers, bruite, avec
des formats internationaux. Les chiffres sont donc plus bas — et plus
honnetes. Une baseline "Presidio brut" (AnalyzerEngine fr, sans les
garde-fous SENTINEL) tourne sur les memes lignes pour comparaison.

Usage :
    python tests/benchmark_external.py                 # 400 lignes (cache)
    python tests/benchmark_external.py --rows 1000     # plus large
    python tests/benchmark_external.py --refresh       # re-telecharge
    python tests/benchmark_external.py --json          # sortie machine

Les donnees sont telechargees via l'API datasets-server de Hugging Face
et mises en cache dans tests/data/ (non versionne : donnees tierces).
"""
from __future__ import annotations
import argparse
import asyncio
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app.detection.engine import DetectionEngine          # noqa: E402
from app.detection.types import EntityType                # noqa: E402

DATASET = "ai4privacy/pii-masking-300k"
SPLIT = "validation"
LANGUAGE = "French"
DATA_DIR = Path(__file__).resolve().parent / "data"
PAGE = 100  # maximum de l'API datasets-server

# Labels ai4privacy -> types SENTINEL. Les labels hors perimetre
# (adresses, dates, usernames...) sont ignores : SENTINEL ne les
# revendique pas, ils ne comptent ni en rappel ni en precision.
LABEL_MAP: dict[str, EntityType] = {
    "EMAIL": EntityType.EMAIL,
    "TEL": EntityType.PHONE_FR,
    "GIVENNAME1": EntityType.PERSON,
    "GIVENNAME2": EntityType.PERSON,
    "LASTNAME1": EntityType.PERSON,
    "LASTNAME2": EntityType.PERSON,
    "LASTNAME3": EntityType.PERSON,
    "SOCIALNUMBER": EntityType.NIR,
    "IBAN": EntityType.IBAN,
    "CREDITCARD": EntityType.CARD,
}

# Baseline : sortie brute de Presidio (memes types, sans garde-fous)
PRESIDIO_BASELINE_MAP = {
    "PERSON": EntityType.PERSON,
    "EMAIL_ADDRESS": EntityType.EMAIL,
    "PHONE_NUMBER": EntityType.PHONE_FR,
    "CREDIT_CARD": EntityType.CARD,
    "IBAN_CODE": EntityType.IBAN,
}


def download_rows(n: int) -> list[dict]:
    import httpx
    rows: list[dict] = []
    where = f"\"language\"='{LANGUAGE}'"
    with httpx.Client(timeout=30.0) as client:
        offset = 0
        while len(rows) < n:
            resp = client.get(
                "https://datasets-server.huggingface.co/filter",
                params={"dataset": DATASET, "config": "default",
                        "split": SPLIT, "where": where,
                        "offset": offset, "length": min(PAGE, n - len(rows))},
            )
            resp.raise_for_status()
            batch = resp.json()["rows"]
            if not batch:
                break
            for r in batch:
                row = r["row"]
                rows.append({
                    "id": row["id"],
                    "text": row["source_text"],
                    "mask": [{"label": m["label"], "start": m["start"],
                              "end": m["end"], "value": m["value"]}
                             for m in row["privacy_mask"]],
                })
            offset += len(batch)
    return rows


def load_rows(n: int, refresh: bool) -> list[dict]:
    DATA_DIR.mkdir(exist_ok=True)
    cache = DATA_DIR / f"ai4privacy_fr_{SPLIT}.json"
    if cache.exists() and not refresh:
        cached = json.loads(cache.read_text(encoding="utf-8"))
        if len(cached) >= n:
            return cached[:n]
    rows = download_rows(n)
    cache.write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")
    return rows


def _overlaps(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return a_start < b_end and a_end > b_start


class Scorer:
    """Correspondance de spans : un span attendu est trouve (TP) si une
    detection du meme type le chevauche ; une detection qui ne chevauche
    aucun span attendu de son type est un faux positif."""

    def __init__(self):
        self.tp = defaultdict(int)
        self.fn = defaultdict(int)
        self.fp = defaultdict(int)

    def score_row(self, gold: list[tuple[EntityType, int, int]],
                  pred: list[tuple[EntityType, int, int]]) -> None:
        for gtype, gs, ge in gold:
            if any(pt == gtype and _overlaps(gs, ge, ps, pe)
                   for pt, ps, pe in pred):
                self.tp[gtype] += 1
            else:
                self.fn[gtype] += 1
        for ptype, ps, pe in pred:
            if not any(gt == ptype and _overlaps(gs, ge, ps, pe)
                       for gt, gs, ge in gold):
                self.fp[ptype] += 1

    def metrics(self, etype: EntityType) -> tuple[float, float, float, int]:
        tp, fn, fp = self.tp[etype], self.fn[etype], self.fp[etype]
        support = tp + fn
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / support if support else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        return prec, rec, f1, support

    def micro(self, types: list[EntityType]) -> tuple[float, float, float]:
        tp = sum(self.tp[t] for t in types)
        fn = sum(self.fn[t] for t in types)
        fp = sum(self.fp[t] for t in types)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        return prec, rec, f1


def presidio_baseline(text: str) -> list[tuple[EntityType, int, int]]:
    from app.detection import l2_ner
    analyzer = l2_ner._get_analyzer()
    out = []
    for r in analyzer.analyze(text=text, language="fr"):
        etype = PRESIDIO_BASELINE_MAP.get(r.entity_type)
        if etype:
            out.append((etype, r.start, r.end))
    return out


async def run(rows: list[dict], with_baseline: bool) -> dict:
    engine = DetectionEngine()
    sentinel = Scorer()
    baseline = Scorer()
    ignored = defaultdict(int)
    latencies = []

    for i, row in enumerate(rows, 1):
        text = row["text"]
        gold = []
        for m in row["mask"]:
            etype = LABEL_MAP.get(m["label"])
            if etype is None:
                ignored[m["label"]] += 1
            else:
                gold.append((etype, m["start"], m["end"]))

        t0 = time.perf_counter()
        result = await engine.analyze(text)
        latencies.append(time.perf_counter() - t0)

        pred = [(f.entity_type, f.start, f.end)
                for f in result.findings
                if "obfuscation" not in f.meta
                and f.entity_type in LABEL_MAP.values()]
        sentinel.score_row(gold, pred)

        if with_baseline:
            baseline.score_row(gold, await asyncio.to_thread(
                presidio_baseline, text))

        if i % 50 == 0:
            print(f"  ... {i}/{len(rows)} lignes", file=sys.stderr)

    types = sorted({t for t in LABEL_MAP.values()}, key=lambda t: t.value)
    return {"sentinel": sentinel, "baseline": baseline if with_baseline else None,
            "types": types, "ignored": dict(ignored), "latencies": latencies}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=400)
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--no-baseline", action="store_true")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()

    rows = load_rows(args.rows, args.refresh)
    print(f"Benchmark externe : {DATASET} ({LANGUAGE}, split {SPLIT}), "
          f"{len(rows)} lignes\n", file=sys.stderr)

    res = asyncio.run(run(rows, not args.no_baseline))
    sentinel, baseline, types = res["sentinel"], res["baseline"], res["types"]

    if args.as_json:
        payload = {"dataset": DATASET, "language": LANGUAGE, "rows": len(rows)}
        for name, scorer in (("sentinel", sentinel), ("presidio", baseline)):
            if scorer is None:
                continue
            payload[name] = {
                t.value: dict(zip(("precision", "recall", "f1", "support"),
                                  scorer.metrics(t)))
                for t in types}
            p, r, f1 = scorer.micro(types)
            payload[name]["micro"] = {"precision": p, "recall": r, "f1": f1}
        print(json.dumps(payload, indent=2))
        return

    lat = res["latencies"]
    print("=" * 74)
    print(f" {'Type':<10} | {'SENTINEL P/R/F1':^24} | "
          f"{'Presidio brut P/R/F1':^24} | Supp.")
    print("-" * 74)
    for t in types:
        p, r, f1, sup = sentinel.metrics(t)
        cell_s = f"{p:5.1%} {r:6.1%} {f1:6.1%}"
        if baseline:
            bp, br, bf1, _ = baseline.metrics(t)
            cell_b = f"{bp:5.1%} {br:6.1%} {bf1:6.1%}"
        else:
            cell_b = "-"
        print(f" {t.value:<10} | {cell_s:^24} | {cell_b:^24} | {sup:>5}")
    print("-" * 74)
    p, r, f1 = sentinel.micro(types)
    line = f" {'MICRO':<10} | {p:5.1%} {r:6.1%} {f1:6.1%}    "
    if baseline:
        bp, br, bf1 = baseline.micro(types)
        line += f" | {bp:5.1%} {br:6.1%} {bf1:6.1%}    "
    print(line)
    print("=" * 74)
    print(f"Latence moyenne : {sum(lat) / len(lat) * 1000:.0f} ms/ligne "
          f"(p95 : {sorted(lat)[int(len(lat) * 0.95)] * 1000:.0f} ms)")
    if res["ignored"]:
        top = sorted(res["ignored"].items(), key=lambda kv: -kv[1])[:8]
        print("Labels hors perimetre ignores :",
              ", ".join(f"{k} ({v})" for k, v in top))


if __name__ == "__main__":
    main()
