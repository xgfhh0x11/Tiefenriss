"""
params.py — Tiefenriss's DATA-ANCHORED political parameters (θ, k, tier thresholds).

DECISION (2026-07-05, researcher approval): θ and the tier labels were moved from the
synthetic-era constants (θ=0.30, D≥0.15/0.55) and anchored to the PERCENTILEs of the REAL G
distribution. Rationale: even if the synthetic constants happen to land on the right percentile today,
they silently drift as the data grows → selectivity changes unnoticed. The percentile-anchor fixes the stance.

STANCE (CHOSEN — political, operational preference):
  • stratejik (deep look)   : G ≥ G_p{STRAT_PCT}   → θ is placed here (D=0.5 exactly here)
  • taktik    (shallow look): G_p{TAKTIK_PCT} ≤ G < G_p{STRAT_PCT}
  • atla                    : G < G_p{TAKTIK_PCT}
  • k (transition sharpness): fixed, not critical (the D≥0.5 count is independent of k)

core.py IS NOT TOUCHED. These are passed as overrides to CoreParams — the core's own
opening()/_classify_tier() runs with these thresholds.

RECOMPUTE: as the data grows call recompute(db) — the percentiles are re-read from fresh G,
the STANCE (p90/p75) stays fixed, the threshold NUMBERS are updated.
"""
from .core_bridge import CoreParams
from cekirdek.core import opening
from . import calibrate

# --- STANCE (percentile anchors) — CHOSEN ---
STRAT_PCT = 90    # stratejik: look deep at the most valuable 10%
TAKTIK_PCT = 75   # taktik base: skip the bottom 75%, look shallow at 75–90%
K = 8.0           # transition sharpness (not critical; can be tuned later)


def _params_from_percentiles(g_p_taktik, g_p_strat, k=K):
    """
    Produce CoreParams from percentile G values. θ = the strategic threshold (G_p_strat);
    the tier D-thresholds are the D equivalent of the relevant G-percentile under the chosen θ,k.
    """
    theta = g_p_strat
    p = CoreParams(theta=theta, k=k)
    # strategic: G ≥ θ  ↔  D ≥ opening(θ) = 0.5 (by definition)
    strat_esik = opening(g_p_strat, p)      # ≈ 0.5
    # tactical base: G ≥ G_p_taktik ↔ D ≥ opening(G_p_taktik)
    taktik_esik = opening(g_p_taktik, p)
    return CoreParams(theta=theta, k=k,
                      tier_taktik_esik=taktik_esik,
                      tier_stratejik_esik=strat_esik)


def recompute(db_path: str):
    """Data-anchored CoreParams from the fresh G distribution. → (CoreParams, anchors dict)."""
    import numpy as np
    Gs, now, n = calibrate.population_G(db_path)
    pos = [g for g in Gs if g > 1e-9]
    g_p_taktik = float(np.percentile(pos, TAKTIK_PCT))
    g_p_strat = float(np.percentile(pos, STRAT_PCT))
    params = _params_from_percentiles(g_p_taktik, g_p_strat)
    anchors = {
        "n_surfaces": n, "now_days": now,
        "STRAT_PCT": STRAT_PCT, "TAKTIK_PCT": TAKTIK_PCT, "k": K,
        "G_p_taktik": g_p_taktik, "G_p_strat_theta": g_p_strat,
        "tier_taktik_esik": params.tier_taktik_esik,
        "tier_stratejik_esik": params.tier_stratejik_esik,
    }
    return params, anchors


# --- SNAPSHOT values (2947 CPE-clean surfaces, published ≤ 2026-06-04) ---
# produced with recompute(); frozen for fast use. Recompute as the data grows.
# Anchors: θ=G_p90=0.1761, taktik base=G_p75=0.0614, k=8.
# History: after the ρ-fix θ 0.226→0.165; after the v0 declaration-alignment (info-leak tier added)
# 0.165→0.176 (info-leak surfaces raised G → upper-percentile nudge). Thanks to the percentile-anchor
# the full-pop split is FIXED every time (74/14/10) — with a frozen θ it would have broken twice.
# DEPENDENCY: this snapshot relies on the declaration-aligned ruler. If CETVEL_BEYANI §5 (info-leak/race)
# CHANGES by researcher decision → recompute with params.recompute(db).
SNAPSHOT_THETA = 0.1761
SNAPSHOT_TAKTIK_G = 0.0614

DEFAULT = _params_from_percentiles(SNAPSHOT_TAKTIK_G, SNAPSHOT_THETA)
