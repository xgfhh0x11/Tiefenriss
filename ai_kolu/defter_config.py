"""
defter_config.py — prediction-notebook CHOSEN-parameters + INVARIANTs.

The values in this file are sealed decisions (2026-07-16). See `A1m2_defter_dolum_TASARIM.md` §5.
"""

# ── HELD-OUT FRACTION (f) — CHOSEN ───────────────────────────────────────────
# Band 10-20%, midpoint 15%. THE REAL RISK is small-f: few held-out → base-rate rests on a few
# surfaces → Poisson-noise (the same KEV 11-CVE underpowered trap). 15% is enough sample for the
# base even in the few-user phase. Large-f's "tool silent" cost is negligible in A-mode.
# LIVE NOTE: check whether held-out-N is enough; if the base is noisy, INCREASE f.
HELD_OUT_FRACTION = 0.15  # CHOSEN

# ── HELD-OUT SEED — INVARIANT (NOT a config-value) ───────────────────────────
# ⚠️ NEVER CHANGED. Its immutability is an INVARIANT, not a tunable option.
# If the seed changes, held-out/highlighted assignment shifts ENTIRELY → the clean-baseline accrued
# until then becomes INVALID (the İ7 clean-baseline window collapses → the baseline is RESET). Don't change it.
HELD_OUT_SEED = "tiefenriss-heldout-v1"  # INVARIANT — if changed the baseline resets

# ── REALIZATION-HORIZON (days), per-direction — CHOSEN ───────────────────────
# Nominal-now (data-constraint). Live: percentile-calibrated; may diverge per-direction.
HORIZON_DAYS_BY_DIRECTION = {
    "ileri": 180,   # discovery: the horizon for a surface to become a stress-point
    "geri": 180,    # operation: nominal (may diverge live)
}
