"""
windows_harness.py — SECOND-DOMAIN (Windows/MSRC) tests: does the value-model generalize beyond Linux?

Corpus: msrc_windows.json (3180 Windows CVEs 2020-26; CWE 69%, Exploitability-Index 98%, title-components).

TESTS:
  1. v0-RULER VALIDATION (new — never possible before): does the DECLARED v0(cwe) correlate with Microsoft's
     expert Exploitability-Index? The v0-ruler was "declared, not calibrated" → first external validation of it.
     (Note: partly reflects shared bug-class signal — which is EXACTLY what validates the ruler's ORDERING.)
  2. GENERALIZATION BACKTEST (temporal, ≤2023 → 2024-26): does v0-density forward-predict future high-value /
     future EXPLOITABLE CVEs on Windows, controlling for activity? Does Linux's +0.333 replicate?
  3. RELATEDNESS: structurally weak on Windows (one title-component per CVE, templated titles) → the Linux
     3-strike (relatedness dead) stands; not re-run here.
"""
from __future__ import annotations

import json
import os

from adapter.ruler import v0_for
from .kaynaklar import DATA_DIR
from .backtest import _rank, _pearson, _spearman, partial_spearman
from .backtest_gb import _partial2

CUTOFF = 2023
HIGH_VALUE = 0.80
EXPLOIT_ORD = {"Unlikely": 0, "Less Likely": 1, "More Likely": 2, "Exploited": 3}
HIGH_EXPLOIT = {"More Likely", "Exploited"}


def _year(cve):
    try:
        return int(cve.split("-")[1])
    except Exception:
        return None


def load():
    return json.load(open(os.path.join(DATA_DIR, "msrc_windows.json"), encoding="utf-8"))


def report():
    corpus = load()
    print("=" * 84)
    print("WINDOWS HARNESS — does the value-model generalize? (v0-ruler validation + backtest)")
    print("=" * 84)
    print(f"\ncorpus: {len(corpus)} Windows CVE · CWE {sum(1 for r in corpus if r['cwe'])} · exploit {sum(1 for r in corpus if r['exploit'])}")

    # ---- TEST 1: v0-ruler vs expert Exploitability-Index (per-CVE) ----
    pairs = [(v0_for([r["cwe"]])[0], EXPLOIT_ORD[r["exploit"]])
             for r in corpus if r["cwe"] and r["exploit"] in EXPLOIT_ORD]
    v0s = [p[0] for p in pairs]; exs = [p[1] for p in pairs]
    sp = _spearman(v0s, exs)
    # mean v0 by exploit-class
    import statistics
    hi = [v0_for([r["cwe"]])[0] for r in corpus if r["cwe"] and r["exploit"] in HIGH_EXPLOIT]
    lo = [v0_for([r["cwe"]])[0] for r in corpus if r["cwe"] and r["exploit"] in ("Less Likely", "Unlikely")]
    print(f"\n[TEST 1] v0-RULER VALIDATION (per-CVE, n={len(pairs)}):")
    print(f"    Spearman(v0, exploitability-index) = {sp:+.3f}")
    print(f"    mean v0: high-exploit(More/Exploited, n={len(hi)})={statistics.mean(hi):.3f}  "
          f"vs low(Less/Unlikely, n={len(lo)})={statistics.mean(lo):.3f}  Δ={statistics.mean(hi)-statistics.mean(lo):+.3f}")
    print(f"    → {'v0-ruler EXTERNALLY VALID (declared tiers align with expert exploitability)' if sp>=0.2 else 'v0-ruler weak/misaligned on Windows'}")

    # ---- TEST 2: generalization backtest (per-component, ≤2023 → 2024-26) ----
    from collections import defaultdict
    tr = defaultdict(lambda: {"n": 0, "v0sum": 0.0, "meas": 0})
    te = defaultdict(lambda: {"n": 0, "meas": 0, "hv": 0, "exn": 0, "hiex": 0})
    for r in corpus:
        y = _year(r["cve"]); comp = r["component"]
        if not comp or y is None:
            continue
        cwe = r["cwe"]
        if y <= CUTOFF:
            tr[comp]["n"] += 1
            if cwe:
                tr[comp]["v0sum"] += v0_for([cwe])[0]; tr[comp]["meas"] += 1
        else:
            te[comp]["n"] += 1
            if cwe:
                te[comp]["meas"] += 1
                if v0_for([cwe])[0] >= HIGH_VALUE:
                    te[comp]["hv"] += 1
            if r["exploit"] in EXPLOIT_ORD:
                te[comp]["exn"] += 1
                if r["exploit"] in HIGH_EXPLOIT:
                    te[comp]["hiex"] += 1

    rows = []
    for c in set(tr) & set(te):
        t, s = tr[c], te[c]
        cov = t["meas"] / t["n"] if t["n"] else 0.0
        mm = t["v0sum"] / t["meas"] if t["meas"] else 0.25
        rows.append({
            "comp": c, "train_v0": cov * mm + (1 - cov) * 0.25, "train_count": t["n"],
            "test_count": s["n"], "test_meas": s["meas"], "test_hv_frac": (s["hv"] / s["meas"]) if s["meas"] else 0.0,
            "test_exploit_rate": (s["hiex"] / s["exn"]) if s["exn"] else 0.0, "test_exn": s["exn"],
        })
    print(f"\n[TEST 2] GENERALIZATION BACKTEST (components in both windows: {len(rows)}):")
    tc = [r["train_count"] for r in rows]; fc = [r["test_count"] for r in rows]
    print(f"    persistence: Spearman(train_count, test_count) = {_spearman(tc, fc):+.3f}")
    # 2a: v0-density → future high-value-CWE fraction (Linux-comparable)
    st = [r for r in rows if r["test_meas"] >= 5]
    pa = _partial2([r["train_v0"] for r in st], [r["test_hv_frac"] for r in st],
                   [float(r["test_count"]) for r in st], [r["train_v0"] for r in st]) if False else \
         partial_spearman([r["train_v0"] for r in st], [r["test_hv_frac"] for r in st], [float(r["test_count"]) for r in st])
    print(f"    [2a] partial(train_v0, future_hv_frac | future_count), n={len(st)} = {pa:+.3f}  (Linux was +0.333)")
    # 2b: v0-density → future EXPLOITABLE rate (the real ground-truth backtest)
    se = [r for r in rows if r["test_exn"] >= 5]
    pb = partial_spearman([r["train_v0"] for r in se], [r["test_exploit_rate"] for r in se], [float(r["test_count"]) for r in se])
    print(f"    [2b] partial(train_v0, future_EXPLOIT_rate | future_count), n={len(se)} = {pb:+.3f}  (value-density → future exploitable?)")

    print(f"\n[TEST 3] relatedness: structurally weak on Windows (1-component/CVE, templated titles) → Linux 3-strike stands.")
    print("=" * 84)
    return rows


if __name__ == "__main__":
    report()
