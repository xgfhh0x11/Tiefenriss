"""
backtest.py — TEMPORAL-HOLDOUT validation of the value-model on the historical CVE timeline (NO waiting).

The question: does the eye's value-model, computed as-of an earlier date, PREDICT where high-value CVEs
actually appear later — ABOVE the trivial "active subsystems stay active" (persistence) baseline?

Split: train ≤ CUTOFF (2019-2023) → compute the model → test > CUTOFF (2024-2026, data we ALREADY have).

Non-trivial claim isolated: π (past count) predicting future count is TRIVIAL (persistence autocorrelates).
The interesting claim is v0 (value-DENSITY): does a subsystem's CWE-value-character (as of 2023) predict that
its 2024-26 CVEs are DISPROPORTIONATELY high-value (memory-corruption)? If yes → the eye sees "value character",
a real persistent forward property — not just activity. That is external evidence, computable NOW.

HONEST CAVEAT: the Linux CNA started Feb-2024 → pre-2024 CVEs are a biased/sparser sample, 2024+ is comprehensive
(regime shift). This inflates VOLUME tests; the VALUE-CHARACTER test (v0→future-hv-fraction) is robust to it
(which subsystems are UAF-dense persists across the volume regime). Audit-bias persists too (correlation, not causation).
"""
from __future__ import annotations

import json
import os
from collections import defaultdict

from adapter.ruler import v0_for
from .kaynaklar import DATA_DIR
from .kaynaklar.kernel_git import norm_subsystem

CUTOFF = 2023
HIGH_VALUE = 0.80          # memory-corruption / race tier (UAF/OOB/type-confusion/race) — the "dangerous primitive"
V0_UNKNOWN = 0.25


def _year(cve: str) -> int | None:
    try:
        return int(cve.split("-")[1])
    except Exception:
        return None


def _primary_subsystem(files: list[str]) -> str | None:
    if not files:
        return None
    count: dict[str, int] = {}
    order: list[str] = []
    for f in files:
        s = norm_subsystem(f)
        if s not in count:
            order.append(s)
        count[s] = count.get(s, 0) + 1
    if not order:
        return None
    return sorted(order, key=lambda s: (-count[s], order.index(s)))[0]


# ---- rank stats (no scipy) ----
def _rank(v):
    order = sorted(range(len(v)), key=lambda i: v[i])
    rk = [0.0] * len(v)
    i = 0
    while i < len(v):
        j = i
        while j + 1 < len(v) and v[order[j + 1]] == v[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            rk[order[k]] = avg
        i = j + 1
    return rk


def _pearson(x, y):
    n = len(x)
    mx, my = sum(x) / n, sum(y) / n
    num = sum((x[i] - mx) * (y[i] - my) for i in range(n))
    dx = sum((v - mx) ** 2 for v in x) ** 0.5
    dy = sum((v - my) ** 2 for v in y) ** 0.5
    return num / (dx * dy) if dx and dy else 0.0


def _spearman(x, y):
    return _pearson(_rank(x), _rank(y))


def _resid_on(y, x):
    n = len(x)
    mx, my = sum(x) / n, sum(y) / n
    vx = sum((v - mx) ** 2 for v in x)
    b = (sum((x[i] - mx) * (y[i] - my) for i in range(n)) / vx) if vx else 0.0
    a = my - b * mx
    return [y[i] - (a + b * x[i]) for i in range(n)]


def partial_spearman(x, y, z):
    rx, ry, rz = _rank(x), _rank(y), _rank(z)
    return _pearson(_resid_on(rx, rz), _resid_on(ry, rz))


def build():
    cf = [json.loads(l) for l in open(os.path.join(DATA_DIR, "census_full.jsonl"), encoding="utf-8") if l.strip()]
    cwe_map = json.load(open(os.path.join(DATA_DIR, "nvd_cwe.json"), encoding="utf-8"))["cwe_map"]

    def cwe_of(cve):
        c = cwe_map.get(cve)
        return c if (c and str(c).startswith("CWE-")) else None

    # per-subsystem accumulators, train (≤CUTOFF) and test (>CUTOFF)
    tr = defaultdict(lambda: {"n": 0, "v0sum": 0.0, "meas": 0})   # train: count, sum-of-measured-v0, measured-count
    te = defaultdict(lambda: {"n": 0, "meas": 0, "hv": 0, "vsum": 0.0})  # test: count, measured, high-value, value-sum
    for r in cf:
        y = r.get("year")
        sub = _primary_subsystem(r.get("files") or [])
        if not sub or sub.startswith("include/"):     # header dirs excluded (non-surfaces, consistent w/ wire_core)
            continue
        cwe = cwe_of(r["cve"])
        if y is not None and y <= CUTOFF:
            tr[sub]["n"] += 1
            if cwe:
                tr[sub]["v0sum"] += v0_for([cwe])[0]; tr[sub]["meas"] += 1
        elif y is not None:
            te[sub]["n"] += 1
            if cwe:
                v = v0_for([cwe])[0]
                te[sub]["meas"] += 1; te[sub]["vsum"] += v
                if v >= HIGH_VALUE:
                    te[sub]["hv"] += 1

    rows = []  # subsystems present in BOTH windows (can predict train→test)
    for sub in set(tr) & set(te):
        t, s = tr[sub], te[sub]
        cov = t["meas"] / t["n"] if t["n"] else 0.0
        mean_meas = t["v0sum"] / t["meas"] if t["meas"] else V0_UNKNOWN
        train_v0 = cov * mean_meas + (1 - cov) * V0_UNKNOWN            # coverage-shrunk density (wire_core-consistent)
        rows.append({
            "sub": sub,
            "train_count": t["n"], "train_v0": train_v0, "train_score": train_v0 * t["n"],  # score ≈ depth (v0×π)
            "test_count": s["n"], "test_meas": s["meas"], "test_hv": s["hv"],
            "test_hv_frac": (s["hv"] / s["meas"]) if s["meas"] else 0.0,
        })
    return rows


def report():
    rows = build()
    N = len(rows)
    print("=" * 82)
    print(f"BACKTEST — value-model as-of {CUTOFF} predicts {CUTOFF+1}-2026 high-value CVEs? (temporal holdout)")
    print("=" * 82)
    print(f"\nsubsystems in BOTH windows: {N}  (train ≤{CUTOFF} → test >{CUTOFF})")

    tc = [r["train_count"] for r in rows]; tv = [r["train_v0"] for r in rows]; ts = [r["train_score"] for r in rows]
    fc = [r["test_count"] for r in rows]; fh = [float(r["test_hv"]) for r in rows]

    # [1] persistence baseline (context: predicting ACTIVITY is trivial)
    print(f"\n[1] PERSISTENCE baseline (trivial): Spearman(train_count, test_count) = {_spearman(tc, fc):+.3f}")
    print(f"    → 'active subsystems stay active' — this is the baseline the model must BEAT for value.")

    # [2] v0 FORWARD-VALIDITY (the real test): does value-density predict future value-CHARACTER, controlling for activity?
    stable = [r for r in rows if r["test_meas"] >= 5]     # stable future high-value fraction only
    sv = [r["train_v0"] for r in stable]; sf = [r["test_hv_frac"] for r in stable]; sfc = [float(r["test_count"]) for r in stable]
    pc = partial_spearman(sv, sf, sfc)
    print(f"\n[2] v0 FORWARD-VALIDITY (n={len(stable)}, test_meas≥5):")
    print(f"    partial-Spearman(train_v0, future_hv_fraction | future_count) = {pc:+.3f}")
    verdict = ("VALID — 2023 value-density predicts 2024-26 value-character above activity (the eye sees 'value')"
               if pc >= 0.25 else
               ("weak/none — value-density has little forward lift beyond activity" if abs(pc) < 0.15
                else f"partial ({pc:+.3f}) — suggestive, not decisive"))
    print(f"    → {verdict}")

    # [3] RANKING LIFT: does depth (v0×count) capture future HIGH-VALUE CVEs better than the count-baseline?
    total_hv = sum(r["test_hv"] for r in rows)
    for K in (10, 20, 40):
        by_depth = sorted(rows, key=lambda r: r["train_score"], reverse=True)[:K]
        by_count = sorted(rows, key=lambda r: r["train_count"], reverse=True)[:K]
        hv_depth = sum(r["test_hv"] for r in by_depth); hv_count = sum(r["test_hv"] for r in by_count)
        print(f"\n[3] RANKING LIFT (top-{K}): future-HV captured — by DEPTH={hv_depth}/{total_hv} ({100*hv_depth/max(total_hv,1):.0f}%) "
              f"vs by COUNT={hv_count}/{total_hv} ({100*hv_count/max(total_hv,1):.0f}%)")

    # [4] top predicted (as-of-2023) vs what they actually produced
    print(f"\n[4] TOP-10 by depth-{CUTOFF} → actual {CUTOFF+1}-2026 outcome:")
    for r in sorted(rows, key=lambda r: r["train_score"], reverse=True)[:10]:
        print(f"    {r['sub']:16s} train(v0={r['train_v0']:.2f}×n={r['train_count']:3d}) → "
              f"future: {r['test_count']:3d} CVE, {r['test_hv']:3d} high-value ({100*r['test_hv_frac']:.0f}% of measured)")
    print("=" * 82)
    return rows


if __name__ == "__main__":
    report()
