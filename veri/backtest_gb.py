"""
backtest_gb.py — does g_B (semantic bug-profile relatedness) ADD forward-validity beyond v0×π? (temporal-clean)

g_B construction (TEMPORAL-CLEAN — only ≤CUTOFF data):
  per ≤2023 CVE → fix-description (vulns CVE-5.0 JSON) → embed (all-MiniLM-L6-v2, local, no API).
  subsystem-embedding = MEAN of its ≤2023 CVE-embeddings (adapter's g_B design).
  g_B = PageRank over the cosine≥0.80 similarity graph (which subsystems fail in SIMILAR ways).

Test (via the backtest harness): does the g_B-augmented value v0·(1+w·g_B) predict 2024-26 high-value CVEs
BETTER than v0 alone — controlling for activity? LOW PRIOR: g_B is relatedness-flow (like g_A, which was
externally-hollow) + partially redundant with v0 (bug-nature ≈ CWE-value). Testing the STRONGEST relatedness
so a negative is CONCLUSIVE (relatedness-flow dead → value is intrinsic v0×π).
"""
from __future__ import annotations

import json
import os

import numpy as np

from adapter.ruler import v0_for
from .kaynaklar import DATA_DIR
from .kaynaklar.kernel_git import norm_subsystem
from .backtest import (CUTOFF, _year, _primary_subsystem, _rank, _pearson, _spearman,
                       partial_spearman, build as backtest_build)

VULNS_ROOT = os.path.join(DATA_DIR, "vulns", "cve")
SIM_THRESHOLD = 0.80
EMB_MODEL = "all-MiniLM-L6-v2"


def _find_json(cve: str) -> str | None:
    year = cve.split("-")[1]
    for sub in ("published", "testing/published", "rejected", "reserved"):
        p = os.path.join(VULNS_ROOT, sub, year, f"{cve}.json")
        if os.path.exists(p):
            return p
    return None


def _description(path: str) -> str | None:
    try:
        d = json.load(open(path, encoding="utf-8"))
        descs = d.get("containers", {}).get("cna", {}).get("descriptions", [])
        return descs[0]["value"] if descs else None
    except Exception:
        return None


def compute_gb() -> dict:
    """g_B per subsystem from ≤CUTOFF CVE-description embeddings. TEMPORAL-CLEAN (no >CUTOFF data touched)."""
    cf = [json.loads(l) for l in open(os.path.join(DATA_DIR, "census_full.jsonl"), encoding="utf-8") if l.strip()]
    # gather ≤CUTOFF (cve, subsystem, description)
    per_sub_desc: dict[str, list[str]] = {}
    n_seen = n_desc = 0
    for r in cf:
        y = r.get("year")
        if y is None or y > CUTOFF:
            continue
        sub = _primary_subsystem(r.get("files") or [])
        if not sub or sub.startswith("include/"):
            continue
        p = _find_json(r["cve"])
        if not p:
            continue
        n_seen += 1
        desc = _description(p)
        if desc:
            n_desc += 1
            per_sub_desc.setdefault(sub, []).append(desc)
    print(f"  ≤{CUTOFF}: {n_seen} CVE JSON found, {n_desc} with-description, {len(per_sub_desc)} subsystem")

    # embed all descriptions, mean per subsystem
    from sentence_transformers import SentenceTransformer
    model = SentenceTransformer(EMB_MODEL)
    subs = list(per_sub_desc)
    flat = [d for s in subs for d in per_sub_desc[s]]
    print(f"  embedding {len(flat)} descriptions ({EMB_MODEL})...")
    embs = model.encode(flat, batch_size=128, show_progress_bar=False, normalize_embeddings=True)
    sub_emb = {}
    i = 0
    for s in subs:
        k = len(per_sub_desc[s])
        sub_emb[s] = np.mean(embs[i:i + k], axis=0)
        i += k

    # cosine-sim graph (embeddings already normalized → dot = cosine), edges ≥ threshold, PageRank
    names = list(sub_emb)
    M = np.vstack([sub_emb[s] for s in names])
    M = M / (np.linalg.norm(M, axis=1, keepdims=True) + 1e-9)
    S = M @ M.T
    np.fill_diagonal(S, 0.0)
    adj = (S >= SIM_THRESHOLD).astype(float) * S     # weighted edges above threshold
    n = len(names)
    deg = adj.sum(axis=1)
    pr = np.ones(n) / n
    for _ in range(100):
        dangling = 0.85 * pr[deg == 0].sum() / n
        nxt = np.full(n, 0.15 / n) + dangling
        contrib = np.where(deg > 0, 0.85 * pr / np.maximum(deg, 1e-9), 0.0)
        nxt += adj.T @ contrib
        pr = nxt
    pr = pr / pr.max() if pr.max() > 0 else pr
    n_edges = int((adj > 0).sum() // 2)
    print(f"  g_B graph: {n} nodes, {n_edges} edges (cosine≥{SIM_THRESHOLD}), isolated={int((deg==0).sum())}")
    return {names[i]: float(pr[i]) for i in range(n)}


def _resid_multi(y, Zs):
    Y = np.array(y, float)
    X = np.column_stack([np.array(z, float) for z in Zs] + [np.ones(len(y))])
    beta, *_ = np.linalg.lstsq(X, Y, rcond=None)
    return list(Y - X @ beta)


def _partial2(x, y, z1, z2):   # partial corr(x,y | z1,z2), rank-based
    rx, ry, rz1, rz2 = _rank(x), _rank(y), _rank(z1), _rank(z2)
    return _pearson(_resid_multi(rx, [rz1, rz2]), _resid_multi(ry, [rz1, rz2]))


def report():
    print("=" * 84)
    print(f"g_B BACKTEST — does semantic bug-profile relatedness ADD forward-validity beyond v0×π? (clean, ≤{CUTOFF})")
    print("=" * 84)
    rows = backtest_build()
    gb = compute_gb()
    for r in rows:
        r["gb"] = gb.get(r["sub"], 0.0)

    N = len(rows)
    tv = [r["train_v0"] for r in rows]; tc = [r["train_count"] for r in rows]
    g = [r["gb"] for r in rows]; fc = [float(r["test_count"]) for r in rows]

    # is g_B even distinct from v0? (redundancy check)
    print(f"\n[redundancy] Spearman(g_B, train_v0) = {_spearman(g, tv):+.3f}  Spearman(g_B, train_count) = {_spearman(g, tc):+.3f}")

    # [A] g_B UNIQUE forward-validity — controlling for future activity AND v0
    stable = [r for r in rows if r["test_meas"] >= 5]
    sg = [r["gb"] for r in stable]; sf = [r["test_hv_frac"] for r in stable]
    sfc = [float(r["test_count"]) for r in stable]; sv = [r["train_v0"] for r in stable]
    pA = _partial2(sg, sf, sfc, sv)
    print(f"\n[A] g_B UNIQUE forward-validity (n={len(stable)}): partial(g_B, future_hv_frac | future_count, train_v0) = {pA:+.3f}")
    print(f"    (v0-alone was +0.333) → {'g_B ADDS signal beyond v0' if pA>=0.2 else 'g_B adds ~nothing beyond v0 (relatedness-flow hollow, confirmed)'}")

    # [B] ranking lift — does v0·(1+w·g_B)×count capture more future-HV than v0×count?
    total_hv = sum(r["test_hv"] for r in rows)
    base = sorted(rows, key=lambda r: r["train_v0"] * r["train_count"], reverse=True)
    print(f"\n[B] RANKING LIFT (future-HV captured; baseline = v0×count):")
    for w in (0.15, 0.5, 1.0):
        aug = sorted(rows, key=lambda r: r["train_v0"] * (1 + w * r["gb"]) * r["train_count"], reverse=True)
        for K in (20, 40):
            b = sum(r["test_hv"] for r in base[:K]); a = sum(r["test_hv"] for r in aug[:K])
            if w == 0.15 and K == 20:
                print(f"    top-{K}: baseline={b}/{total_hv} ({100*b/total_hv:.0f}%)")
            print(f"    top-{K} w={w}: g_B-aug={a}/{total_hv} ({100*a/total_hv:.0f}%)  Δ={a-b:+d}")

    print("=" * 84)
    return rows


if __name__ == "__main__":
    report()
