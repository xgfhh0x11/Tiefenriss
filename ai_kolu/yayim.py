"""
yayim.py — A2.5 EMIT TO NOTEBOOK: candidate-battery → boundary → admitted to the notebook, rejects to the reject-log.

Each admitted atom → dolum.record_prediction (exposure assigned BLIND, single-anchor SOURCE-surface,
new A2 fields). cat-2 → pending-detector (notebook-view). cat-3 → not emitted (reject-log).
A2 exposure-BLIND: it also writes to held-out surfaces (control-group); the curtain is AT PRESENTATION (user_visible).

A-TYPE measurement-anchor (2026-07-18): a candidate without a tier-snapshot is REJECTED (the old silent `or "atla"` default
produced trivial-realization; İ9b). The snapshot must come from the kernel (adapter_bridge); otherwise reject-log.
"""
from __future__ import annotations

from .boundary import admit
from .dolum import record_prediction
from .a2_types import Candidate


def emit_batch(defter, candidates: list[Candidate], created_ts: str, provenance: str = "") -> dict:
    """
    Pass the candidate-battery through the boundary and emit to the notebook. Returns:
      {admitted_map: {key: pred_id}, red_log: [...], counts: {...}}
    red_log: structured-summary + reason + empty-field (decision §5.3 — is the lens bad or the prompt bad).

    `provenance` (status-typed-record discipline): WHICH operator produced it (e.g. "Fable-5-production" vs
    "Opus-as-operator"). Written to Ongoru.note → the #Ç4-baseline reads the right-operator's performance
    (does not attribute to the wrong-operator). Empty → old behavior.
    """
    admitted_map: dict[str, str] = {}
    red_log: list[dict] = []
    n_cat1 = n_cat2 = 0

    def _red(c, reason, field):
        red_log.append({
            "key": c.key, "source_lens": c.source_lens, "pred_type": c.pred_type.value,
            "vuln_class": c.vuln_class, "reason": reason, "empty_field": field,
        })

    for c in candidates:
        res = admit(c)
        if not res.admitted:
            _red(c, res.reason, res.empty_field)
            continue
        # A-TYPE measurement-anchor: if there is NO tier-snapshot realization can't be measured (base_rank=None in the detector →
        # forever unmeasurable). The old `or "atla"` silent-default produced trivial-realization (any
        # tier rises above atla) → an İ9b violation (garbage silently-NOT-FIXED). The snapshot comes from the kernel
        # (adapter_bridge); otherwise REJECT + quarantine (reject-log). In the real pipeline A2 only runs on a tiered surface.
        if not (c.tier_at_creation or "").strip():
            _red(c, "tier-snapshot yok (gerçekleşme-çapası ölçülemez)", "tier_at_creation")
            continue
        o = record_prediction(
            defter, surface_id=c.surface_id, direction=c.direction,
            content=c.mechanism, created_ts=created_ts,
            tier_at_creation=c.tier_at_creation, note=provenance,   # WHICH operator produced it (baseline-honesty)
            pred_id=c.key,   # deterministic traceability (test); derived in production
            pred_type=c.pred_type, target_ref=c.target_ref,
            vuln_class=c.vuln_class, mechanism=c.mechanism,
            falsification_method=c.falsification_method,
            measurement_category=res.measurement_category,
            pending_detector=res.pending_detector, source_lens=c.source_lens,
        )
        admitted_map[c.key] = o.pred_id
        if res.measurement_category and res.measurement_category.value == "2":
            n_cat2 += 1
        else:
            n_cat1 += 1

    return {
        "admitted_map": admitted_map, "red_log": red_log,
        "counts": {"admitted": len(admitted_map), "rejected": len(red_log),
                   "cat1": n_cat1, "cat2": n_cat2},
    }
