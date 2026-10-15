"""
measure.py — the system's FIRST OUTPUTS (v2.1 §12: not solved at the desk, read from data).

Three measurements:
  #Ç1  A/C ratio        — is value from the measured neighborhood (Type A)?  (C does not exist
                          architecturally; here: value's g_A share vs g_B share — read A's weight.)
  #Ç2  g_B/g_A ratio    — how DERIVED (B) vs MEASURED (A) is the gate? w calibration.
  #Ç3  "does g rise first?" — the basis of the HARD VETO. ONE-WAY (see below).

╔══════════════════════════════════════════════════════════════════════════╗
║ #Ç3 IS ONE-WAY — a negative result proves NOTHING.                        ║
║   g = g_A + w·g_B. This corpus has NO g_B(t) (embeddings timestamp-less).  ║
║   Only g_A(t) is visible. Therefore:                                       ║
║     • g_A rises BEFOREHAND  → HARD VETO is supported (POSITIVE, works)     ║
║     • g_A does not rise     → does NOT MEAN the veto is wrong; maybe it was ║
║                               rising in g_B, we didn't see it (UNPROVEN).  ║
║   So only a positive result carries info. Decision obeys this asymmetry.   ║
╚══════════════════════════════════════════════════════════════════════════╝
"""
from datetime import timedelta
from statistics import mean, median

from .core_bridge import evaluate
from .positions import compute_g_A
from . import build as _build


def measure_AC_and_gBgA(profiles: dict, decisions: dict, w: float):
    """
    #Ç1 (A/C→A share) + #Ç2 (g_B/g_A). decisions: {sid: DepthDecision}.
    Value decomposition: value = v0·g_A (A) + v0·w·g_B (B).
    """
    a_shares, ratios, gA_vals, gB_vals = [], [], [], []
    hi_a_shares = []
    for sid, (prof, meta) in profiles.items():
        gA = prof.graph_pos.g_A
        gB = prof.graph_pos.g_B
        A_part = prof.v0 * gA
        B_part = prof.v0 * w * gB
        denom = A_part + B_part
        a_share = A_part / denom if denom > 0 else None
        if a_share is not None:
            a_shares.append(a_share)
            if decisions[sid].tier != "atla":
                hi_a_shares.append(a_share)
        if gA > 0:
            ratios.append(gB / gA)
        gA_vals.append(gA)
        gB_vals.append(gB)

    return {
        "n": len(profiles),
        "AC_A_share_mean": mean(a_shares) if a_shares else None,
        "AC_A_share_mean_nonskip": mean(hi_a_shares) if hi_a_shares else None,
        "gB_over_gA_mean": mean(ratios) if ratios else None,
        "gB_over_gA_median": median(ratios) if ratios else None,
        "gA_mean": mean(gA_vals) if gA_vals else None,
        "gB_mean": mean(gB_vals) if gB_vals else None,
        "n_with_embedding": sum(1 for _, (_, m) in profiles.items() if m["has_embedding"]),
    }


def measure_C3(all_surfaces: dict, subset_sids: set, decisions: dict,
               core_params, w: float):
    """
    #Ç3 ONE-WAY, g_A-only, UNDERPOWERED (46d window).

    Method: split the window in the middle. g_A_early = the PageRank of the graph built
    only from early-half CVEs. g_A_late = the full graph (global). Each surface's D_final from
    the full profile. Question: were the surfaces that end high-D ALREADY well positioned in the
    early period (g_A_early ≥ g_A_late·τ)? If so "g rose first" → POSITIVE (in favor of the veto).
    Otherwise UNPROVEN (g_B invisible).
    """
    all_days = [d for s in all_surfaces.values() for d in s.days]
    min_day, max_day = min(all_days), max(all_days)
    mid = min_day + timedelta(days=(max_day - min_day).days // 2)

    # early-half surface universe: surfaces whose first member is before mid,
    # with their members clipped up to mid
    early = {}
    for k, s in all_surfaces.items():
        edays = [d for d in s.days if d <= mid]
        if edays:
            from .surfaces import Surface
            es = Surface(s.cwe, s.vp)
            es.members = s.members[:len(edays)]
            es.days = edays
            early[k] = es
    g_A_early, _ = compute_g_A(early)   # early global position

    # full (late) global position
    g_A_late, _ = compute_g_A(all_surfaces)

    TAU = 0.8  # CHOSEN threshold: "early position ≥80% of late position" = risen beforehand
    rows = []
    for sid in subset_sids:
        d = decisions[sid]
        ge = g_A_early.get(sid, 0.0)
        gl = g_A_late.get(sid, 0.0)
        early_positioned = (gl > 0 and ge >= gl * TAU)
        rows.append({
            "sid": sid, "tier": d.tier, "D": d.depth,
            "g_A_early": ge, "g_A_late": gl,
            "early_positioned": early_positioned,
        })

    hi = [r for r in rows if r["tier"] != "atla"]
    lo = [r for r in rows if r["tier"] == "atla"]   # CONTROL GROUP
    hi_pos = [r for r in hi if r["early_positioned"]]
    lo_pos = [r for r in lo if r["early_positioned"]]

    # ARTEFACT TEST: how much does g_A MOVE? (if early≈late then #Ç3 is trivially positive)
    deltas = [abs(r["g_A_late"] - r["g_A_early"]) for r in rows if r["g_A_late"] > 0]
    # CONTROL: does early-positioning DISTINGUISH high-D from atla?
    #   if it doesn't (the two ratios ~same) → early-position is an artefact, #Ç3 carries no proof.
    return {
        "mid_day": mid.isoformat(),
        "n_subset": len(rows),
        "n_highD": len(hi),
        "n_highD_early_positioned": len(hi_pos),
        "frac_highD_early_positioned": (len(hi_pos) / len(hi)) if hi else None,
        "frac_skip_early_positioned": (len(lo_pos) / len(lo)) if lo else None,   # control
        "mean_abs_gA_shift": mean(deltas) if deltas else None,                    # artefact diagnosis
        "median_abs_gA_shift": median(deltas) if deltas else None,
        "mean_gA_early_highD": mean([r["g_A_early"] for r in hi]) if hi else None,
        "mean_gA_late_highD": mean([r["g_A_late"] for r in hi]) if hi else None,
        "rows": sorted(rows, key=lambda r: -r["D"])[:15],
    }
