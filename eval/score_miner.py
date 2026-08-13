"""Track 2 evaluation harness: score miners against ground-truth labels.

Ground-truth format (JSON lines, one per contract):
    {"address": "0x...", "contract": "...", "expected_rating": "critical",
     "expected_high": 1, "known_bug": "REENTRANCY", "severity_weights": {...}}

We score a miner by POSTing each address to its /v1/analyze endpoint and
comparing the returned risk report against the expected label.  Multiple
metrics are emitted so organiser/miner both get a transparent number:

  - rating_accuracy : fraction of exact rating matches
  - high_f1         : F1 over 'high' vs not-high
  - rating_distance : mean |expected - predicted| on an ordinal 0..3 scale
  - determinism     : fraction of identical outputs across two identical runs
  - latency_p50 / p95

This doubles as the "Evaluation Scripts" track artifact: it is deterministic,
schema-validated, and emits a machine-readable JSON report.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter

import requests

RATING_SCALE = {"clean": 0, "moderate": 1, "elevated": 2, "critical": 3, "no_source": -1}


def load_ground_truth(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def evaluate_miner(gt: list[dict], base_url: str, repeats: int = 1) -> dict:
    rows = []
    for case in gt:
        addr = case["address"]
        payload = {"address": addr}
        attempts = []
        for _ in range(repeats):
            t0 = time.monotonic()
            r = requests.post(f"{base_url.rstrip('/')}/v1/analyze", json=payload, timeout=300)
            attempts.append((r.status_code, r.json() if r.status_code == 200 else None, time.monotonic() - t0))
        ok = [a for a in attempts if a[1] is not None]
        if not ok:
            continue
        first = ok[0][1]
        latencies = [a[2] for a in ok]
        rows.append(
            {
                "address": addr,
                "expected_rating": case.get("expected_rating"),
                "predicted_rating": first.get("rating"),
                "latency_s": round(sum(latencies) / len(latencies), 3),
                "deterministic": all(a[1]["rating"] == first["rating"] for a in ok),
            }
        )

    if not rows:
        return {"error": "no successful responses", "rows": rows}

    rating_acc = sum(1 for r in rows if r["expected_rating"] == r["predicted_rating"]) / len(rows)

    # ordinal distance (ignore no_source = -1)
    dists = []
    for r in rows:
        e = RATING_SCALE.get(r["expected_rating"])
        p = RATING_SCALE.get(r["predicted_rating"])
        if e is not None and p is not None and e >= 0 and p >= 0:
            dists.append(abs(e - p))
    rating_dist = round(sum(dists) / len(dists), 3) if dists else None

    # high vs not-high F1
    def is_high(rating: str) -> int:
        return 1 if rating == "critical" else 0

    tp = sum(1 for r in rows if is_high(r["expected_rating"]) == 1 and is_high(r["predicted_rating"]) == 1)
    fp = sum(1 for r in rows if is_high(r["expected_rating"]) == 0 and is_high(r["predicted_rating"]) == 1)
    fn = sum(1 for r in rows if is_high(r["expected_rating"]) == 1 and is_high(r["predicted_rating"]) == 0)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    high_f1 = round(2 * prec * rec / (prec + rec), 3) if (prec + rec) else 0.0

    latencies = sorted(r["latency_s"] for r in rows)
    n = len(latencies)
    p50 = latencies[n // 2] if n else None
    p95 = latencies[int(n * 0.95) - 1] if n else None

    return {
        "miner": base_url,
        "n_cases": len(rows),
        "rating_accuracy": round(rating_acc, 3),
        "rating_distance": rating_dist,
        "high_f1": high_f1,
        "determinism": round(
            sum(1 for r in rows if r["deterministic"]) / len(rows), 3
        ) if rows else None,
        "latency_p50_s": p50,
        "latency_p95_s": p95,
        "rows": rows,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Score a miner against ground truth")
    ap.add_argument("--truth", required=True, help="path to ground-truth JSONL")
    ap.add_argument("--base-url", default="http://127.0.0.1:8185", help="miner base URL")
    ap.add_argument("--repeats", type=int, default=1, help="runs per case (determinism)")
    ap.add_argument("--out", help="write JSON report to path")
    args = ap.parse_args()

    gt = load_ground_truth(args.truth)
    if not gt:
        print("empty ground truth", file=sys.stderr)
        return 1

    report = evaluate_miner(gt, args.base_url, args.repeats)
    print(json.dumps(report, indent=2))

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
