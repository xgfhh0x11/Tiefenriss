"""
veri_bridge.py — ai_kolu → veri/ bridge: new value-substrate → AI-arm SurfaceContext + tier-map.

ANALOGUE of `adapter_bridge` but a NEW substrate (veri/ wire_core: v=v0-density, depth=v0×π-calibrated,
reachability-separate-axis, g_A lowered). One-way dependency (ai_kolu → veri → cekirdek; never the reverse).
Read-only. Tier/ceiling come from the kernel's OWN depth-calibration-decision (verdict from the kernel).

Kernel-richness is carried into `SurfaceContext.note` (reachability/CWE-distribution/depth/coverage) — so the
operator consumes this substrate better. OPEN-fraction is MARKED (status doesn't leak): cwe='OPEN' + coverage-note.
"""
from __future__ import annotations

from veri.wire_core import scored_surfaces
from .llm_operator import SurfaceContext


def veri_surface_tiers() -> dict:
    """{subsystem: tier} — dolum's tier_at_creation snapshot + the detector's current_tier are fed from this."""
    return {r["subsystem"]: r["tier"] for r in scored_surfaces()}


def _kernel_note(r: dict) -> str:
    dist = ", ".join(f"{k}×{v}" for k, v in sorted(r["cwe_dist"].items(), key=lambda x: -x[1])[:4]) or "—"
    routing = "makine-#Ç4" if r["reach"] == "reachable" else "insan-kol"
    seam = "ARAYÜZ-dikişi" if r["is_interface"] else "yaprak"
    return (f"kernel-substrat: reachability={r['reach']} ({routing}) · {seam} · "
            f"depth={r['depth']:.2f} · π={r['pi']:.0f} (sinyal-birikimi) · "
            f"CWE-dağılımı[{dist}] · kapsam={r['coverage']:.0%} (AÇIK-fraksiyon işaretli, ölçülmüş-sanma)")


def veri_contexts(top_n: int | None = None) -> list[SurfaceContext]:
    """
    New-substrate SurfaceElements → the list of SurfaceContexts the operator will consume (depth-sorted).
    cwe = the mode of the measured-distribution (else 'OPEN'). n_members = cve_count (signal-pulses). Richness in note.
    """
    rows = scored_surfaces()
    if top_n:
        rows = rows[:top_n]
    out = []
    for r in rows:
        out.append(SurfaceContext(
            surface_id=r["subsystem"], cwe=r["cwe_mode"], vp=r["subsystem"], tier=r["tier"],
            n_members=r["cve_count"], day_span=r["span"],
            n_places=1, places_sample=[r["reach"]],
            note=_kernel_note(r),
        ))
    return out
