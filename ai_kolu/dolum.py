"""
dolum.py — prediction-notebook WRITE-PATH + held-out assignment (İ7).

Responsibility: when recording a type-2 prediction into the notebook, assign exposure + horizon + tier_at_creation.
Does NOT PRODUCE predictions (that's the A2 AI-generator) — this is only record-infrastructure. Day-1 (İ7 clean-baseline starts).
DETERMINISTIC, NO AI. One-way (ai_kolu → adapter/cekirdek).
"""
import hashlib

from .ongoru_defteri import Ongoru, Direction, Exposure, PredType, MeasurementCategory
from . import defter_config as cfg


def assign_exposure(surface_id: str, seed: str | None = None,
                    fraction: float | None = None) -> Exposure:
    """
    SURFACE-unit seeded-random exposure (İ7 + module-2 §3 refinement).

    Why random not-structural: held-out being the gold-standard-base depends on it being an unbiased
    sample from the SAME population as highlighted (RCT control-group). Structural → biased → base collapses.

    Why SURFACE-unit: NO prediction about a held-out surface is shown → genuinely
    attention-free (if it were prediction-unit, a sibling-highlighted would leak attention).

    Why hashlib (NOT Python hash()): hash() is process-salted → CHANGES across machines/reruns.
    sha256 is deterministic + reproducible. Independent of surface-features (unbiased).
    """
    seed = cfg.HELD_OUT_SEED if seed is None else seed
    fraction = cfg.HELD_OUT_FRACTION if fraction is None else fraction
    h = hashlib.sha256(f"{surface_id}|{seed}".encode("utf-8")).hexdigest()
    bucket = int(h, 16) % 10000
    return Exposure.HELD_OUT if bucket < fraction * 10000 else Exposure.HIGHLIGHTED


def record_prediction(defter, surface_id: str, direction: Direction, content: str,
                      created_ts: str, tier_at_creation: str,
                      seed: str | None = None, fraction: float | None = None,
                      pred_id: str | None = None, note: str = "",
                      pred_type: PredType = PredType.STRESS_POINT, target_ref: str | None = None,
                      vuln_class: str | None = None, mechanism: str = "",
                      falsification_method: str = "",
                      measurement_category: MeasurementCategory | None = None,
                      pending_detector: str | None = None, source_lens: str | None = None) -> Ongoru:
    """
    Write a type-2 prediction into the notebook:
      • exposure  ← surface-unit seeded-random (assign_exposure)  [A2 exposure-BLIND: by the source surface]
      • horizon   ← per-direction CHOSEN default (defter_config)
      • tier_at_creation ← prediction-moment kernel-tier snapshot (so realization is measured without params-drift)
      • A2 fields (vuln_class/mechanism/falsification_method/measurement_category/source_lens/pred_type/target_ref)
    exposure IMMUTABLE. SINGLE-ANCHOR: surface_id = SOURCE (in a transition the target is in target_ref, not the anchor). If pred_id
    is not given it is derived deterministically.
    """
    exposure = assign_exposure(surface_id, seed, fraction)
    horizon = cfg.HORIZON_DAYS_BY_DIRECTION.get(direction.value)
    pid = pred_id or f"{surface_id}|{direction.value}|{pred_type.value}|{created_ts}"
    o = Ongoru(
        pred_id=pid, surface_id=surface_id, direction=direction, content=content,
        created_ts=created_ts, exposure=exposure, horizon_days=horizon,
        tier_at_creation=tier_at_creation, note=note,
        pred_type=pred_type, target_ref=target_ref, vuln_class=vuln_class, mechanism=mechanism,
        falsification_method=falsification_method, measurement_category=measurement_category,
        pending_detector=pending_detector, source_lens=source_lens,
    )
    defter.record(o)
    return o
