"""
calibrate.py — calibrate the θ/k POLITICAL parameters to the real-data G distribution.

v2.1 §8: θ (the opening threshold) and k (the transition sharpness) are POLITICAL — they define
not "reality" but "what I will do". So there is NO SINGLE CORRECT θ; θ is a STANCE (how selective?).
This module DOES NOT IMPOSE θ: it reads the G distribution, produces the θ→tier curve, and offers
a reasoned suggestion. The final stance is the researcher's.

CRITICAL: G = v^p·(α·π + β·ρ) → INDEPENDENT of θ/k. G is computed once, θ/k is swept
analytically. D = D_max·σ(k(G−θ)) depends on θ/k only here. core.py IS NOT TOUCHED —
the core's own opening()/_classify_tier() functions are called with different CoreParams.

POPULATION: ALL CPE-clean surfaces (2947), not 141. Single-pulse surfaces define
the noise floor; θ must sit ON TOP of them. Calibrating with 141 (signal-filtered) would
give a wrongly-low θ.
g_B: only EXISTING embeddings (regenerate=False) — calibration is g_A-dominant, fast.
"""
import argparse
from collections import Counter
from statistics import quantiles

import numpy as np

from .core_bridge import CoreParams, evaluate
from cekirdek.core import opening, _classify_tier  # the core's own functions
from .surfaces import load_surfaces, DB_DEFAULT
from .positions import compute_g_A
from .embeddings import surface_embeddings
from .positions import compute_g_B
from .build import build_profiles


def _pct(vals, ps):
    a = np.asarray(vals, dtype=float)
    return {p: float(np.percentile(a, p)) for p in ps}


def population_G(db_path: str, regenerate_gB: bool = False):
    """
    G values of the whole CPE-clean surface universe (independent of θ/k). → (Gs, now, n_surf).
    Calibration + param derivation are fed from here (the single source of truth).
    """
    all_surf, footprint = load_surfaces(db_path, min_pulses=1)
    g_A, _ = compute_g_A(all_surf)
    emb = surface_embeddings(all_surf, db_path, regenerate=regenerate_gB)
    g_B, _ = compute_g_B(emb)
    profiles, now = build_profiles(all_surf, g_A, g_B, footprint)
    Gs = [evaluate(prof, now, CoreParams()).tension for _, (prof, _) in profiles.items()]
    return Gs, now, len(all_surf)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DB_DEFAULT)
    args = ap.parse_args()

    base = CoreParams()
    print("=" * 78)
    print("TIEFENRISS — θ/k CALIBRATION (POLITICAL; core.py untouched, CoreParams override)")
    print("=" * 78)

    # 1. the whole CPE-clean universe
    all_surf, footprint = load_surfaces(args.db, min_pulses=1)
    print(f"[1] population: {len(all_surf)} CPE-clean surfaces (all — noise floor included)")

    # 2. g_A global, g_B existing-embedding
    g_A, _ = compute_g_A(all_surf)
    emb = surface_embeddings(all_surf, args.db, regenerate=False)
    g_B, _ = compute_g_B(emb)
    print(f"[2] g_A global ({len(g_A)}), g_B existing-embedding ({len(emb)} surfaces)")

    # 3. profiles + G (independent of θ/k) once
    profiles, now = build_profiles(all_surf, g_A, g_B, footprint)
    Gs = [evaluate(prof, now, base).tension for _, (prof, _) in profiles.items()]
    Gs_pos = [g for g in Gs if g > 1e-9]
    print(f"[3] G computed ({len(Gs)} surfaces, now={now:.0f}d). "
          f"G>0: {len(Gs_pos)} (gate v^p vetoed {len(Gs)-len(Gs_pos)} to ~0)")

    # 4. G distribution
    pcs = _pct(Gs, [50, 75, 90, 95, 99])
    pcs_pos = _pct(Gs_pos, [50, 75, 90, 95, 99]) if Gs_pos else {}
    print("\n  G distribution (all):      p50={:.3f} p75={:.3f} p90={:.3f} p95={:.3f} p99={:.3f} max={:.2f}"
          .format(pcs[50], pcs[75], pcs[90], pcs[95], pcs[99], max(Gs)))
    print("  G distribution (G>0 subset): p50={:.3f} p75={:.3f} p90={:.3f} p95={:.3f} p99={:.3f}"
          .format(pcs_pos.get(50,0), pcs_pos.get(75,0), pcs_pos.get(90,0),
                  pcs_pos.get(95,0), pcs_pos.get(99,0)))

    # 5. θ-SWEEP (k fixed=8), then the k effect
    def dist(theta, k):
        p = CoreParams(theta=theta, k=k)
        c = Counter(_classify_tier(opening(g, p), p) for g in Gs)
        opened = sum(1 for g in Gs if opening(g, p) >= 0.5)
        return c, opened

    print("\n  θ-SWEEP (k=8, D_max=1, tier thresholds D≥0.15 taktik / D≥0.55 stratejik):")
    print(f"    {'θ':>6} {'atla':>6} {'taktik':>7} {'stratejik':>10} {'D≥0.5':>7}  (over 2947)")
    theta_grid = [0.15, 0.30, 0.50, 0.75, 1.00, 1.50, 2.00, 3.00]
    for th in theta_grid:
        c, op = dist(th, 8.0)
        star = "  ← current default" if abs(th - base.theta) < 1e-9 else ""
        print(f"    {th:>6.2f} {c['atla']:>6} {c['taktik']:>7} {c['stratejik']:>10} {op:>7}{star}")

    print("\n  k EFFECT (θ=p90={:.2f}; k transition sharpness):".format(pcs_pos.get(90, 1.0)))
    thk = pcs_pos.get(90, 1.0)
    for k in [4.0, 8.0, 16.0]:
        c, op = dist(thk, k)
        print(f"    k={k:>4.0f}  atla={c['atla']:>5} taktik={c['taktik']:>5} "
              f"stratejik={c['stratejik']:>5}  D≥0.5={op}")

    # 6. reasoned suggestion (stance → θ), NOT AN IMPOSITION
    print("\n" + "=" * 78)
    print("SUGGESTION (θ POLITICAL — the final stance is yours; below is a data-reasoned candidate)")
    print("=" * 78)
    print("  Logic: the gate v^p already vetoed low value. θ, WITHIN the G>0 mass that passes")
    print("  the gate, separates the 'noise floor' from 'real tension'. Stance→θ mapping:")
    for stance, p in [("aggressive (open wide)", 50), ("balanced", 75), ("selective (open narrow)", 90)]:
        th = pcs_pos.get(p, 0.0)
        c, op = dist(th, 8.0)
        print(f"    • {stance:<20} θ≈G_p{p}(>0)={th:.2f} → "
              f"atla={c['atla']} taktik={c['taktik']} stratejik={c['stratejik']}")
    print("  NOTE: the current θ=0.30 was chosen for the synthetic range (π~O(1-4)). The real WHOLE-universe")
    print(f"  G>0 median is {pcs_pos.get(50,0):.3f}, θ=0.30 ≈ G_p92 → on the full population")
    print(f"  ALREADY selective (74% atla). The early 'too strategic' impression was a 141-subset artefact.")
    print(f"  WARNING: G is extremely right-skewed (median {pcs_pos.get(50,0):.3f}, max {max(Gs):.1f}) → tier")
    print(f"  boundaries are HYPER-SENSITIVE at θ∈[0.2,0.4] (a small θ change moves thousands of surfaces).")
    print("  Also the tier-label thresholds (D≥0.15/0.55) should be reviewed together with θ")
    print("  (a downstream companion decision — outside θ/k scope but related).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
