"""
run_poc.py — Tiefenriss adapter + end-to-end PoC.

Flow (CPE-CLEAN surfaces, NO keyword-guessing):
  1. DB → all CPE-clean surfaces (the full universe for g_A GLOBAL position)
  2. PoC subset: surfaces pulsed on ≥2 DIFFERENT days (temporal π real), cap
  3. g_A (global, MEASURED) + g_B (subset embedding, DERIVED)
  4. Surface → ElementProfile → core evaluate() → DepthDecision
  5. Three measurements: A/C, g_B/g_A, #Ç3 (one-way)

DISCIPLINE: small subset first, validate, be suspicious of too-good results.
The Prozessfall DB is READ-ONLY — nothing is written.
"""
import argparse

from .core_bridge import CoreParams, evaluate
from . import params as tief_params
from .surfaces import load_surfaces, DB_DEFAULT
from .positions import compute_g_A, compute_g_B, W_CPE
from .embeddings import surface_embeddings
from .build import build_profiles
from . import measure
from .hints import direction_hints, format_hint


def select_subset(surfaces, min_days=2, cap=250):
    """
    PoC population: surfaces pulsed on ≥min_days DIFFERENT days (temporal π real).

    CAUTION — we DO NOT CAP by richness. In the first attempt, selecting the "richest surfaces"
    produced a selection-artefact (all saturated strategic). This gate (≥min_days) is a QUALITY
    filter (is there a temporal signal?), NOT a richness ranking. cap is only a safety
    ceiling; if the number of qualifying surfaces is below cap, all are evaluated → honest distribution.
    """
    cand = [(k, s) for k, s in surfaces.items()
            if len(set(s.days)) >= min_days]
    cand.sort(key=lambda kv: kv[1].sid)  # deterministic, richness-neutral
    return dict(cand[:cap])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DB_DEFAULT)
    ap.add_argument("--cap", type=int, default=250)
    ap.add_argument("--min-days", type=int, default=2)
    ap.add_argument("--synthetic-params", action="store_true",
                    help="veri-çapalı yerine sentetik CoreParams() kullan (karşılaştırma)")
    ap.add_argument("--gb-scope", choices=["global", "subset"], default="global",
                    help="g_B konumu tüm evren (global, gerçek) mi alt-küme-göreli (üst-sınır) mi")
    ap.add_argument("--emb-cache", default=None,
                    help="embedding npz cache yolu (DB'ye değil; tekrar-koşu hızlanır)")
    args = ap.parse_args()

    p = CoreParams() if args.synthetic_params else tief_params.DEFAULT
    src = "SYNTHETIC" if args.synthetic_params else "DATA-ANCHORED (θ=G_p90, tier=G_p75/p90)"
    print("=" * 78)
    print("TIEFENRISS — ADAPTER PoC  (CPE-clean surfaces; DB read-only)")
    print(f"params [{src}]: λ={p.lam} w={p.w} θ={p.theta:.3f} k={p.k} gate_p={p.gate_p} "
          f"tier(D≥{p.tier_taktik_esik:.2f}/{p.tier_stratejik_esik:.2f}) | "
          f"g_A = CPE-only (W_CPE={W_CPE}; CWE-edge REMOVED — hub-popularity)")
    print("=" * 78)

    # 1. the whole CPE-clean surface universe (g_A global position)
    all_surf, cwe_footprint = load_surfaces(args.db, min_pulses=1)
    print(f"[1] CPE-clean surface universe: {len(all_surf)}  "
          f"(CWE footprint: {len(cwe_footprint)} classes)")

    # 2. PoC subset
    subset = select_subset(all_surf, min_days=args.min_days, cap=args.cap)
    print(f"[2] PoC subset (≥{args.min_days} different-day, cap {args.cap}): "
          f"{len(subset)} surfaces")

    # 3. g_A (global), g_B (global OR subset-relative)
    g_A, nA = compute_g_A(all_surf)
    print(f"[3a] g_A computed (global) — {nA} edges, {len(g_A)} surface positions")
    gb_pop = all_surf if args.gb_scope == "global" else subset
    print(f"[3b] generating g_B embeddings ({args.gb_scope}: members of {len(gb_pop)} surfaces)"
          + ("..." if args.gb_scope == "global" else ""))
    surf_emb = surface_embeddings(gb_pop, args.db,
                                  regenerate=True, cache_path=args.emb_cache)
    g_B, nB = compute_g_B(surf_emb)
    n_sub_emb = sum(1 for s in subset.values() if s.sid in g_B)
    print(f"[3b] g_B computed ({args.gb_scope}) — {len(surf_emb)} surfaces with embedding, "
          f"{nB} sim≥0.80 edges | {n_sub_emb}/{len(subset)} of the subset positioned")

    # 4. profiles + core decision (only the subset is evaluated)
    profiles, now = build_profiles(subset, g_A, g_B, cwe_footprint)
    decisions = {sid: evaluate(prof, now, p) for sid, (prof, _) in profiles.items()}
    tiers = {}
    for d in decisions.values():
        tiers[d.tier] = tiers.get(d.tier, 0) + 1
    print(f"[4] evaluate() → tier distribution: {tiers}  (now={now:.0f}d)")

    # TOO-GOOD SUSPICION diagnosis: are the π/ρ scales consistent with the calibration?
    pis = sorted(d.persistence for d in decisions.values())
    rhos = sorted(d.spread for d in decisions.values())
    print(f"    [diag] π range: {pis[0]:.2f} … {pis[-1]:.2f} (median {pis[len(pis)//2]:.2f})"
          f"  |  ρ range: {rhos[0]:.2f} … {rhos[-1]:.2f}")
    print(f"    [diag] π median ~1.25 consistent with the synthetic regime; only the dense tail (π~50)"
          f" saturates at D=1.0 (Finding 3, feature). θ/tier DATA-ANCHORED (params.py); since the subset"
          f" is signal-filtered, less 'atla' is expected than full-pop.")

    # sample highest-D surfaces (eyeball validation — too good?)
    print("\n  Highest-D 10 surfaces (eyeball check):")
    top = sorted(profiles.items(), key=lambda kv: -decisions[kv[0]].depth)[:10]
    for sid, (prof, meta) in top:
        d = decisions[sid]
        print(f"    D={d.depth:.3f} {d.tier:9s} v={d.value:.3f} π={d.persistence:.2f} "
              f"ρ={d.spread:.2f} | g_A={prof.graph_pos.g_A:.3f} g_B={prof.graph_pos.g_B:.3f} "
              f"v0={prof.v0:.2f}[{meta['v0_status']}] pulses={meta['n_pulses']} | {sid}")

    # 4b. DIRECTION-HINT LAYER (keyword, DERIVED — DOES NOT ENTER THE SCORE, shown separately)
    hints = direction_hints(subset, args.db)
    scored = [sid for sid, _ in top]
    hinted = [sid for sid in decisions if sid in hints]
    print(f"\n  DIRECTION-HINTS (keyword, DERIVED · low-confidence · DOES NOT ENTER THE SCORE · 'where to look'):")
    print(f"    coverage: {len(hinted)}/{len(subset)} scored surfaces got a hint "
          f"(richest where CPE lumps; empty on non-kernel surfaces = honest)")
    shown = [sid for sid in scored if sid in hints]
    for sid in shown:
        d = decisions[sid]
        print(f"    [{d.tier:9s} D={d.depth:.2f}] {sid}")
        print(f"        → {format_hint(hints[sid])}")
    if not shown:
        print("    (no kernel-keyword matching surface in the highest-D 10)")

    # 5. MEASUREMENTS
    print("\n" + "=" * 78)
    print("THREE MEASUREMENTS (the system's first outputs)")
    print("=" * 78)
    m12 = measure.measure_AC_and_gBgA(profiles, decisions, p.w)
    print("\n#Ç1 — A/C ratio (C does NOT exist architecturally → value's g_A/A share):")
    print(f"    value's A-share (all): {m12['AC_A_share_mean']:.3f}  "
          f"(on non-skipped surfaces: {m12['AC_A_share_mean_nonskip']})")
    print(f"    → if A-share is high, value is from the MEASURED neighborhood (epistemic-clean)")
    scope_lbl = ("GLOBAL — real weight" if args.gb_scope == "global"
                 else "SUBSET-RELATIVE — UPPER BOUND")
    print(f"\n#Ç2 — g_B/g_A ratio (how DERIVED the gate is) [{scope_lbl}]:")
    print(f"    g_B/g_A mean: {m12['gB_over_gA_mean']:.3f}  median: {m12['gB_over_gA_median']:.3f}")
    print(f"    g_A mean: {m12['gA_mean']:.3f}  g_B mean: {m12['gB_mean']:.3f}  "
          f"(with embedding: {m12['n_with_embedding']}/{m12['n']})")
    print("    → if high, most of the gate is derived (epistemic risk); if low, measured")

    m3 = measure.measure_C3(all_surf, {s.sid for s in subset.values()}, decisions, p, p.w)
    print("\n#Ç3 — 'does g rise first?' (ONE-WAY, g_A-only, UNDERPOWERED):")
    print(f"    mid-day split: {m3['mid_day']} | high-D surfaces: {m3['n_highD']}")
    fr = m3['frac_highD_early_positioned']
    fs = m3['frac_skip_early_positioned']
    print(f"    early-positioned high-D: {m3['n_highD_early_positioned']}/{m3['n_highD']}"
          + (f" ({fr:.0%})" if fr is not None else ""))
    print(f"    [CONTROL] early-positioned ATLA-surface: {fs:.0%}" if fs is not None else "")
    print(f"    [ARTEFACT DIAGNOSIS] g_A's early→late mean shift: "
          f"{m3['mean_abs_gA_shift']:.3f} (median {m3['median_abs_gA_shift']:.3f})")
    print(f"    high-D g_A_early mean: {m3['mean_gA_early_highD']:.3f}  "
          f"g_A_late mean: {m3['mean_gA_late_highD']:.3f}")
    print("    COMMENT: positive ONLY IF (a) the high-D rate is clearly HIGHER than the atla-rate and")
    print("           (b) the g_A shift is non-zero is it meaningful. Otherwise g_A is static → artefact,")
    print("           #Ç3 UNPROVEN (and g_B is invisible). A negative already proves nothing.")

    print("\n" + "=" * 78)
    print("PoC DONE — numbers above. Deviations/decisions will be reported.")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
