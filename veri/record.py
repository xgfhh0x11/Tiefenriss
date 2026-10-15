"""
record.py — RECORD TYPES + TWO-ROLE source interfaces + Zone + DomainProfile.

Two-role source (NOT a single interface — different downstream):
  • SurfaceSource      → produces PartialSurface (a surface-fragment). Consumed by AI DISCOVERY.
  • RealizationSource  → produces RealizationEvent (a prediction-confirming EVENT). Consumed by #Ç4/TIME-GATE.

A surface does not come from a single source: sources produce PARTIAL (status-typed) records; `merge.py`
builds the per-CVE MergedRecord status-preservingly; `aggregate.py` builds the (subsystem,domain)-keyed
SurfaceElement. `refs`/`zone` are first-class (refs=chain/interface signal; zone=realization-routing).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Protocol, runtime_checkable

from .status import Attribute


# ---------------------------------------------------------------------------
# ZONE — realization-routing (for the AI-arm; design-now-build-later)
# ---------------------------------------------------------------------------
class Zone(str, Enum):
    """
    Realization-reachability of a surface (T4: two-channel). `SurfaceElement.zone` is an Attribute (carries a
    Zone value, status-typed — the classification may be MEASURED or still OPEN).
      REACHABLE — syscall/fuzz reachable → machine-#Ç4 (syzbot GIVES forward-realization).
      HARDWARE  — hardware-bound → syzbot BLIND → human-arm judges (cold zone).
    """
    REACHABLE = "reachable"
    HARDWARE = "hardware"


# ---------------------------------------------------------------------------
# PARTIAL SURFACE — a surface-fragment produced by one source
# ---------------------------------------------------------------------------
@dataclass
class PartialSurface:
    """
    A PARTIAL surface produced by a single source. All fields are status-typed (Attribute). Merged on `key`
    (cve_id). E.g. kernel-git → {subsystem:MEASURED, cwe:OPEN}; NVD → {cwe:MEASURED}.
    """
    key: str                              # merge key (e.g. cve_id)
    domain: str                           # scope (linux-kernel / hypervisor / microarch / ...)
    source_name: str                      # which source produced it (top-level provenance)
    fields: dict[str, Attribute] = field(default_factory=dict)   # subsystem/cwe/refs/zone/...


# ---------------------------------------------------------------------------
# MERGED RECORD — per-CVE, status-preservingly merged from many sources (merge output)
# ---------------------------------------------------------------------------
@dataclass
class MergedRecord:
    """
    `merge()` output — a SINGLE CVE merged across sources (subsystem+commit ⋈ CWE). `fields` merged
    status-preservingly. `refs`/`zone` first-class. NOT the surface-ELEMENT: the element the core scores is
    built from THESE via `aggregate()` ((subsystem,domain)-keyed).
    (Decision-a, 2026-07-19: CWE is NOT part of the key → OPEN-CVE preserved; subsystem is always-MEASURED anchor.)
    """
    key: str                              # cve_id (merge key)
    domain: str
    fields: dict[str, Attribute]
    refs: Attribute                       # cross-reference — LOAD-BEARING (chain/interface signal)
    zone: Attribute                       # realization-zone (value: Zone; status-typed)
    source_traces: list[str] = field(default_factory=list)

    def field(self, name: str) -> Attribute | None:
        return self.fields.get(name)

    def as_dict(self) -> dict:
        return {
            "key": self.key, "domain": self.domain,
            "fields": {n: a.as_dict() for n, a in self.fields.items()},
            "refs": self.refs.as_dict(), "zone": self.zone.as_dict(),
            "source_traces": list(self.source_traces),
        }


# ---------------------------------------------------------------------------
# SURFACE ELEMENT — (subsystem, domain)-keyed aggregate (the element the core scores)
# ---------------------------------------------------------------------------
@dataclass
class SurfaceElement:
    """
    `aggregate()` output — subsystem-keyed element aggregating CVEs. CWE is NOT the key: `cwe` is an
    AGGREGATE-Attribute (distribution + coverage; OPEN-fraction marked). v0 is derived from this distribution
    and carries the OPEN-fraction as uncertainty. `is_interface`=guest-host/arch seam element
    (T4: value lives in chains/interfaces → seam first-class).
    """
    key: tuple                            # (subsystem, domain) — always-MEASURED anchor
    subsystem: str
    domain: str
    cve_keys: list[str]                   # the CVEs aggregated into this element
    cve_count: int
    cwe: Attribute                        # AGGREGATE: {distribution, measured_n, derived_n, open_n, total, coverage}
    refs: Attribute                       # aggregated cross-reference (union, status-preserved)
    zone: Attribute                       # element-level realization-zone (aggregate)
    is_interface: bool = False            # interface-subsystem (kvm/xen/virt/arch-boundary) — first-class seam

    def as_dict(self) -> dict:
        return {
            "key": list(self.key), "subsystem": self.subsystem, "domain": self.domain,
            "cve_count": self.cve_count, "cve_keys": list(self.cve_keys),
            "cwe": self.cwe.as_dict(), "refs": self.refs.as_dict(), "zone": self.zone.as_dict(),
            "is_interface": self.is_interface,
        }


# ---------------------------------------------------------------------------
# REALIZATION EVENT — a prediction-confirming EVENT (NOT a surface)
# ---------------------------------------------------------------------------
@dataclass
class RealizationEvent:
    """
    A reality-EVENT confirming a prediction/surface. NOT a surface (separate role, separate downstream:
    #Ç4/time-gate). `status`: syzbot→QUARANTINED (reachable-zone, audit-bias), verified-advisory→MEASURED.
    İ9a: engagement is NEVER counted as realization — this type is built only from REALITY events.
    """
    surface_key: str                      # which surface it confirms (match key)
    event_type: str                       # "syzbot-crash" / "coordinated-advisory" / ...
    when: str                             # event time (caller-supplied)
    status: object                        # Status — QUARANTINED (syzbot) | MEASURED (verified advisory)
    zone: Zone                            # reachable→forward-realization possible / hardware→blind
    provenance: str
    reason: str = ""


# ---------------------------------------------------------------------------
# TWO-ROLE SOURCE INTERFACES (source-agnosticism lives here)
# ---------------------------------------------------------------------------
@runtime_checkable
class SurfaceSource(Protocol):
    """Produces SURFACES. New domain = new SurfaceSource; the layer is not rewritten (staged-scope)."""
    name: str
    def produce(self) -> Iterable[PartialSurface]: ...


@runtime_checkable
class RealizationSource(Protocol):
    """Produces REALIZATION EVENTS (separate role). syzbot/advisory implement this."""
    name: str
    def produce(self) -> Iterable[RealizationEvent]: ...


# ---------------------------------------------------------------------------
# DOMAIN PROFILE — per-domain value weights (small, latent)
# ---------------------------------------------------------------------------
@dataclass
class DomainProfile:
    """
    The core's political parameters (w/α/β/θ/k) per domain. The CORE READS them (v=v0·g_A SEALED,
    untouched); the ADAPTER SUPPLIES them per-domain. T4: kernel → v0-dominant, g_A-bounded (small w).
    """
    domain: str
    w: float          # g_B (embedding) weight — small in kernel (g_A/g_B bounded-modifier)
    alpha: float      # π (accumulation) weight
    beta: float       # ρ (spread) weight
    theta: float      # G threshold (σ center)
    k: float          # σ steepness
    note: str = ""


# T4-derived default: kernel is v0-dominant, g_A/g_B bounded → small w. (Political choice; revised by measurement.)
KERNEL_PROFILE = DomainProfile(
    domain="linux-kernel", w=0.15, alpha=0.6, beta=0.4, theta=0.5, k=1.0,
    note="T4: value v0-dominant, g_A bounded-modifier → w kept small (CHOSEN, revise by measurement)",
)
