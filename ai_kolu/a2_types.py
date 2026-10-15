"""
a2_types.py — A2 pipeline types: the operator-produced Candidate + boundary result types.

Candidate = the RAW candidate produced by the operator (STUB in Pass-1, LLM in Pass-2). The boundary (boundary.py)
PROJECTS it onto the typed-schema + categorizes it THREE-WAY; admitted = type-2 atom, not-admitted = rejection.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .ongoru_defteri import Direction, PredType


class SignalKind(str, Enum):
    """The kind of falsification-method (A2.3 THREE-WAY input)."""
    TIER_CROSSING = "tier_crossing"      # today's detector measures → category-1
    FUTURE_DETECTOR = "future_detector"  # concrete-future-measurement → category-2 (must be BOUNDED, guard)
    NONE = "none"                        # measurement-undefined → category-3 → REJECT (philosophy)


@dataclass
class Candidate:
    """The operator's raw candidate (pre-boundary). The lens free-produces; the boundary disciplines."""
    key: str                      # stable key for test/tracing
    surface_id: str               # SOURCE surface (single-anchor)
    direction: Direction
    pred_type: PredType           # STRESS_POINT (node) | TRANSITION (edge)
    vuln_class: str               # proposed CWE (outside closed-set → reject)
    mechanism: str                # exploit-mechanism (empty → reject)
    signal_kind: SignalKind
    falsification_method: str     # falsification-method text (empty → reject)
    source_lens: str              # provenance
    target_ref: str | None = None         # target-surface for TRANSITION
    detector_name: str | None = None      # named detector for FUTURE_DETECTOR (cat-2)
    signal_horizon_days: int | None = None  # cat-2 horizon (must be BOUNDED; unbounded → reject)
    tier_at_creation: str | None = None   # adapter_bridge snapshot (passed at emission)


@dataclass
class AdmitResult:
    """Boundary decision. If admitted=False, reason+empty_field go to the reject-log."""
    candidate: Candidate
    admitted: bool
    measurement_category: object = None   # MeasurementCategory | None
    pending_detector: str | None = None
    reason: str = ""              # rejection reason
    empty_field: str = ""         # which-field is problematic (reject-log analysis: lens or prompt)
