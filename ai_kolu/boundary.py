"""
boundary.py — A2.3 BOUNDARY: candidate → typed falsifiable atom, OR rejection. DETERMINISTIC.

CENTRAL PRINCIPLE: the boundary tests FALSIFIABILITY, not CONVENTIONALITY.
  if `falsification_method`/`signal_kind` can be filled it passes (novel-but-testable is preserved);
  if measurement-undefined it rejects (untestable-but-deep is discarded). "Does it look technical?" is NOT ASKED.

THREE-WAY (decision §5.1) + three guards:
  cat-1 (TIER_CROSSING) → measured now.
  cat-2 (FUTURE_DETECTOR) → pending-detector; GUARD: detector-name EXISTS + horizon BOUNDED (else hidden cat-3).
  cat-3 (NONE / method-empty) → REJECT (philosophy).
Also: vuln_class CWE-CLOSED-SET (v0 families), mechanism filled, transition → target-ref.
"""
from __future__ import annotations

from adapter.ruler import _TIER   # v0-ruler CWE families = closed-set (one-way: ai_kolu→adapter)
from .ongoru_defteri import MeasurementCategory, PredType
from .a2_types import Candidate, SignalKind, AdmitResult
from .realization_detector import TIER_RANK   # single-source tier-hierarchy (ceiling = max)

CWE_CLOSED_SET = frozenset(_TIER)          # vulnerability-class closed-set (28 families)
MAX_FEASIBLE_HORIZON_DAYS = 3 * 365        # CHOSEN: if cat-2 horizon exceeds this "never-resolves" = hidden cat-3
CEILING_TIER = max(TIER_RANK, key=TIER_RANK.get)   # "stratejik" — can't-rise-above (tier-crossing dead)


def admit(c: Candidate) -> AdmitResult:
    """Pass a candidate through the boundary. → AdmitResult (admitted + category, or reject + reason/field)."""
    def red(reason, field):
        return AdmitResult(c, False, reason=reason, empty_field=field)

    # 1) vulnerability-class CLOSED-SET (not free-text → boundary strict + measurement-clean + v0-consistent)
    if c.vuln_class not in CWE_CLOSED_SET:
        return red(f"vuln_class kapalı-küme dışı: {c.vuln_class}", "vuln_class")

    # 2) mechanism must be filled (empty → incomplete claim)
    if not c.mechanism.strip():
        return red("mekanizma boş", "mechanism")

    # 3) transition (edge) → target-ref required (single-anchor source; target is a separate field)
    if c.pred_type is PredType.TRANSITION and not (c.target_ref or "").strip():
        return red("geçiş(kenar) hedef-ref yok", "target_ref")

    # 4) THREE-WAY — falsification-method
    if not c.falsification_method.strip():
        return red("yanlışlama-yöntemi boş", "falsification_method")
    if c.signal_kind is SignalKind.NONE:
        return red("ölçüm-tanımsız → kategori-3 (felsefe)", "signal_kind")
    if c.signal_kind is SignalKind.TIER_CROSSING:
        # CEILING-GUARD (AU-1 operational): if the surface is already at the ceiling "tier rises UP" is IMPOSSIBLE →
        # this "falsification" is positively-unfalsifiable (can only LAPSE) = secretly-untestable cat-1.
        # Label-honesty backstop: if the operator says tier_crossing at the ceiling, REJECT, force to cat-2
        # (fine/weaponization/colocation detector). The evaluated subset is 60% stratejik → critical.
        if (c.tier_at_creation or "") == CEILING_TIER:
            return red(f"tavan-surface ({CEILING_TIER}): tier-crossing yanlışlanamaz (yukarı-aşamaz) → "
                       "kat-2 ince-detector kullan", "signal_kind")
        return AdmitResult(c, True, measurement_category=MeasurementCategory.SIMDI)
    # FUTURE_DETECTOR → cat-2, GUARDS (bounded+distinctive; else laundered cat-3)
    if c.signal_kind is SignalKind.FUTURE_DETECTOR:
        if not (c.detector_name or "").strip():
            return red("kat-2 detector-adı yok (sınırsız = gizli kat-3)", "detector_name")
        h = c.signal_horizon_days
        if h is None or h <= 0 or h > MAX_FEASIBLE_HORIZON_DAYS:
            return red(f"kat-2 ufuk fizibilitesiz ({h}) = gizli kat-3", "signal_horizon_days")
        return AdmitResult(c, True, measurement_category=MeasurementCategory.PENDING_DETECTOR,
                           pending_detector=c.detector_name)

    return red(f"bilinmeyen signal_kind: {c.signal_kind}", "signal_kind")
