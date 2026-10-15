"""
veri/ — Status-Typed Source-Agnostic Data Layer.

Result of the T4 research phase (first real build). The core is SEALED + element-agnostic (UNTOUCHED);
this layer is DATA ONLY. Staged-scope adds a new source per expansion, without rewriting the layer.
See `veri/TASARIM.md`.

(Package folder still named `veri/` — folder-rename to `data/` deferred to a separate careful turn.
 Code language is English per the permanent rule; conceptual comments / design docs may stay Turkish.)
"""
from .status import Attribute, DisciplineError, Status, StatusTransition, TRUST_ORDER
from .record import (
    DomainProfile, KERNEL_PROFILE, MergedRecord, PartialSurface, RealizationEvent,
    RealizationSource, SurfaceElement, SurfaceSource, Zone,
)
from .merge import merge, CANONICAL_FIELDS, FILLERS
from .aggregate import aggregate, aggregate_cwe, aggregate_zone, merge_refs

__all__ = [
    "Attribute", "DisciplineError", "Status", "StatusTransition", "TRUST_ORDER",
    "DomainProfile", "KERNEL_PROFILE", "MergedRecord", "PartialSurface", "RealizationEvent",
    "RealizationSource", "SurfaceElement", "SurfaceSource", "Zone",
    "merge", "CANONICAL_FIELDS", "FILLERS", "aggregate", "aggregate_cwe", "aggregate_zone", "merge_refs",
]
