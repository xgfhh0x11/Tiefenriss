"""
build.py — THE HEART OF THE ADAPTER: Surface → the core's ElementProfile.

Source and epistemic status of each signal:
  v0           ← ruler.v0_for(primary_cwe)          CHOSEN (static ruler)
  g_A          ← positions.compute_g_A (global)      MEASURED (Type A, shared CPE — CPE-only)
  g_B          ← positions.compute_g_B (subset)      DERIVED (Type B, embedding ≥0.80)
  signals      ← surface.days → Signal(t=day)        MEASURED (publication dates = pulses)
  spread_count ← len(surface.places)                 MEASURED (surface's OWN spread)
  element_id   ← surface.sid                          opaque label (core does not account for it)

TIME BASE: t = (day − global_min_day).days, integer days. now = global_max_day.
λ=0.05 (core default) → half-life ~14d in day units; fits the 46-day window.

spread_count (ρ) — FIXED: ρ = the number of DISTINCT vendor:product that the surface's
MEMBERS touch (SPECIFIC to the surface, NOT cwe-footprint). The old definition (cwe-footprint)
double-counted on fine-grained surfaces: all 14 subsystem-fragments of CWE-416 inherited the same ρ
and became artificially strategic (compare_subsystem finding). The new definition is surface-specific:
a narrow surface (single place) → ρ≈low → "deep/narrow type" (v2.1: high π, ρ≈0), carried by π. A surface that
truly spreads to many places → high ρ → "spread type". In this corpus most surfaces are narrow → ρ weak,
G is carried by v·π (honest).
"""
from datetime import date

from .core_bridge import ElementProfile, GraphPosition, Signal
from . import ruler


def build_profiles(surfaces: dict, g_A: dict, g_B: dict, cwe_footprint: dict = None):
    """
    surfaces: {(cwe,vp): Surface}, g_A/{sid:val}, g_B/{sid:val}.
    cwe_footprint: no longer USED for ρ (kept in the signature for backward-compat; ρ comes from surface.places).
    → {sid: (ElementProfile, meta)}. now (the global current moment) is also returned.
    """
    all_days = [d for s in surfaces.values() for d in s.days]
    if not all_days:
        raise ValueError("no dated pulses — signals cannot be built")
    min_day, max_day = min(all_days), max(all_days)
    now = float((max_day - min_day).days)

    profiles = {}
    for s in surfaces.values():
        v0, v0_status = ruler.v0_for([s.cwe])
        gpos = GraphPosition(
            g_A=g_A.get(s.sid, 0.0),
            g_B=g_B.get(s.sid, 0.0),   # 0.0 if no embedding (blind, not hidden)
        )
        signals = [Signal(t=float((d - min_day).days)) for d in s.days]
        spread_count = len(s.places)          # surface's OWN spread (no double-count)

        prof = ElementProfile(
            v0=v0,
            graph_pos=gpos,
            signals=signals,
            spread_count=spread_count,
            element_id=s.sid,
        )
        meta = {
            "v0_status": v0_status,
            "n_pulses": len(s.members),
            "n_days": len(set(s.days)),
            "has_embedding": s.sid in g_B,
            "cwe": s.cwe,
            "vp": s.vp,
        }
        profiles[s.sid] = (prof, meta)
    return profiles, now
