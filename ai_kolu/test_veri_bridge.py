"""
test_veri_bridge.py — DETERMINISTIC test: the new value-substrate (veri/) flows into the AI-arm. NO live LLM.

Verifies the connection (mirrors Pass-1 discipline: architecture first, live LLM later):
  T1 bridge produces valid SurfaceContexts from REAL kernel surfaces (subsystem/tier/cwe/n_members)
  T2 tier/ceiling come from the new depth-calibration (stratejik → at_ceiling; taktik → not)
  T3 kernel-richness (reachability/CWE-distribution/depth) reaches the operator prompt (note carried)
  T4 tier-map feeds snapshots; OPEN-fraction marked (no status-leak: no_cwe surface → cwe='OPEN')
  T5 the new tiers flow through the boundary: taktik tier-crossing ADMITS, ceiling(stratejik) tier-crossing REJECTED (ceiling-guard)
"""
from __future__ import annotations

from .veri_bridge import veri_contexts, veri_surface_tiers
from .llm_operator import build_prompt, CEILING_TIER
from .boundary import admit
from .a2_types import Candidate, SignalKind
from .ongoru_defteri import Direction, PredType


def _cand(surface_id: str, tier: str, signal=SignalKind.TIER_CROSSING) -> Candidate:
    return Candidate(
        key=f"k::{surface_id}", surface_id=surface_id, direction=Direction.ILERI,
        pred_type=PredType.STRESS_POINT, vuln_class="CWE-416",
        mechanism="freed object reused via racing syscall path → controllable UAF write",
        signal_kind=signal,
        falsification_method="a future CVE on this surface crosses the core tier upward",
        source_lens="teknik", tier_at_creation=tier,
    )


def main() -> int:
    passed = failed = 0

    def check(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1; print(f"  ✓ {label}")
        else:
            failed += 1; print(f"  ✗ {label}")

    ctxs = veri_contexts()
    tiers = veri_surface_tiers()

    # --- T1 valid contexts from real surfaces ---
    check(len(ctxs) > 100, f"T1 bridge produced {len(ctxs)} contexts from real kernel surfaces")
    top = ctxs[0]
    check(bool(top.surface_id) and top.tier in ("atla", "taktik", "stratejik") and top.n_members >= 1,
          f"T1 top context valid: {top.surface_id} tier={top.tier} cve={top.n_members}")

    strat = next((c for c in ctxs if c.tier == "stratejik"), None)
    tak = next((c for c in ctxs if c.tier == "taktik"), None)
    check(strat is not None and tak is not None, "T1 both stratejik and taktik surfaces exist in substrate")

    # --- T2 tier/ceiling from the new depth-calibration ---
    check(strat.at_ceiling and strat.tier == CEILING_TIER, f"T2 stratejik surface at_ceiling ({strat.surface_id})")
    check(not tak.at_ceiling, f"T2 taktik surface NOT at_ceiling ({tak.surface_id})")

    # --- T3 kernel-richness reaches the operator prompt ---
    _sys, user = build_prompt(strat, "teknik")
    check("reachability=" in user and "CWE-dağılımı" in user and "depth=" in user,
          "T3 kernel-substrate note (reachability/CWE-dist/depth) carried into the prompt")
    check("TAVAN" in user, "T3 ceiling-rule present in prompt for stratejik surface")

    # --- T4 tier-map + OPEN-fraction marked (no leak) ---
    check(tiers.get(strat.surface_id) == "stratejik", "T4 tier-map agrees with context tier (snapshot source)")
    open_ctx = next((c for c in ctxs if c.cwe == "OPEN"), None)
    check(open_ctx is not None and "kapsam=" in (open_ctx.note or ""),
          "T4 no_cwe surface → cwe='OPEN' + coverage marked (AÇIK not treated as measured)")

    # --- T5 new tiers flow through the boundary (ceiling-guard on new depth-tiers) ---
    r_ok = admit(_cand(tak.surface_id, "taktik"))
    check(r_ok.admitted, f"T5 taktik tier-crossing ADMITS ({tak.surface_id})")
    r_ceil = admit(_cand(strat.surface_id, "stratejik"))
    check(not r_ceil.admitted and "tavan" in r_ceil.reason.lower(),
          f"T5 ceiling(stratejik) tier-crossing REJECTED by tavan-guard ({strat.surface_id})")

    print(f"\n  veri-bridge: {passed} passed / {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
