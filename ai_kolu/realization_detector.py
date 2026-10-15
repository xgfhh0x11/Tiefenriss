"""
realization_detector.py — the MEASUREMENT-ORGAN of the time-gate (İ5). DETERMINISTIC, NO AI.

The referee is REALITY: measures whether pending type-2 predictions have realized via kernel-tier-movement.
It passes NO JUDGMENT (accuracy-evaluation = #Ç4 downstream). Only type-1 promotion feeds the tight-loop (İ3).

CRITERION (2026-07-16 decision): did the surface rise above the kernel's tier-boundary from
`tier_at_creation`. The verdict comes FROM THE KERNEL (no separate realization-threshold is invented). Comparison against
params-drift is relative to the `tier_at_creation` snapshot.
"""
from datetime import date

from .ongoru_defteri import Realization

# SAME order as the kernel cekirdek/core.py `_classify_tier`: atla < taktik < stratejik
TIER_RANK = {"atla": 0, "taktik": 1, "stratejik": 2}


def _days_between(a_iso: str, b_iso: str) -> int:
    return (date.fromisoformat(b_iso[:10]) - date.fromisoformat(a_iso[:10])).days


def detect(defter, current_tier: dict, now_ts: str) -> dict:
    """
    Compare pending (BEKLIYOR) predictions against reality, update the notebook:
      • current_tier[surface] rank > tier_at_creation rank        → GERCEKLESTI (type-1 promotion)
      • otherwise + realization-horizon exceeded                  → LAPSED (negative≠evidence; permanent)
      • unmeasurable (surface not in pipeline / snapshot missing) + within horizon → unmeasurable (don't touch)
      • otherwise                                                 → BEKLIYOR (don't touch)

    current_tier: {surface_id: tier} — from the adapter pipeline (dependency-injected → the detector is PURE).
    now_ts: ISO — supplied by the CALLER (now() not embedded → deterministic/testable).

    NOTE (known simplification): unmeasurable + horizon-exceeded → counted as LAPSED (the prediction used its chance,
    realization not observed). Separating a data-gap from "stayed-flat" is a live-refinement.
    """
    promoted = lapsed = still_pending = unmeasurable = 0
    for o in list(defter.pending()):
        cur = current_tier.get(o.surface_id)
        base_rank = TIER_RANK.get(o.tier_at_creation) if o.tier_at_creation else None
        cur_rank = TIER_RANK.get(cur) if cur is not None else None

        if cur_rank is not None and base_rank is not None and cur_rank > base_rank:
            defter.promote_to_tip1(o.pred_id, now_ts)      # REALIZED — crossed the kernel-tier
            promoted += 1
        elif o.horizon_days is not None and _days_between(o.created_ts, now_ts) > o.horizon_days:
            defter.mark_lapsed(o.pred_id, now_ts)          # horizon exceeded, no realization
            lapsed += 1
        elif cur_rank is None or base_rank is None:
            unmeasurable += 1                              # unmeasurable, within horizon → don't touch
        else:
            still_pending += 1                             # measurable, not yet crossed → wait
    return {"promoted": promoted, "lapsed": lapsed,
            "still_pending": still_pending, "unmeasurable": unmeasurable}
