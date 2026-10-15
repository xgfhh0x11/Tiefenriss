"""
aggregate.py — per-CVE MergedRecord → (subsystem,domain)-keyed SurfaceElement aggregation.

Decision-a (2026-07-19): CWE is NOT part of the key. subsystem is the always-MEASURED anchor (from the
commit-path, needs no join); CWE rides on top. So an OPEN-CWE CVE (~39%) is NOT LOST — it enters its
subsystem, and its CWE is carried at element level as a DISTRIBUTION+COVERAGE (OPEN-fraction marked).

surface-CWE = AGGREGATE-Attribute:
  value  = {distribution:{cwe:count}, measured_n, derived_n, open_n, quarantined_n, total, coverage}
  status = OPEN if coverage==0 (no measured CWE at all); otherwise MEASURED (the distribution over the
           measured subset IS a real measurement — OPEN ones are NOT fabricated, counted honestly as open_n).
           No invented threshold; the only special case is "nothing measured". v0 reads the distribution and
           weights uncertainty by coverage.
"""
from __future__ import annotations

from .status import Attribute
from .record import MergedRecord, SurfaceElement, Zone


# Interface/seam subsystems (T4: the only real positive was the guest-host interface; value lives in
# chains/interfaces). Prefix match; if the subsystem-path starts with one of these it is a first-class seam element.
INTERFACE_PREFIXES = (
    "arch/x86/kvm", "arch/arm64/kvm", "arch/", "virt/kvm", "virt/",
    "drivers/xen", "drivers/vhost", "drivers/vfio", "drivers/virtio",
)


def _is_interface(subsystem: str) -> bool:
    """Whether the subsystem is a guest-host/hardware-software seam (made a first-class element)."""
    s = subsystem or ""
    return any(s.startswith(p) for p in INTERFACE_PREFIXES)


def aggregate_cwe(group: list[MergedRecord], when: str) -> Attribute:
    """
    Aggregate the CWEs of an element's CVEs into a distribution+coverage. NO fabrication: only MEASURED CWEs
    enter the distribution; OPEN ones are counted as open_n (not lost, not filled). Derived/quarantined counted separately.
    """
    distribution: dict[str, int] = {}
    measured_n = derived_n = open_n = quarantined_n = 0
    for r in group:
        a = r.field("cwe")
        if a is None or a.is_open():
            open_n += 1
        elif a.is_measured():
            distribution[a.value] = distribution.get(a.value, 0) + 1
            measured_n += 1
        elif a.is_derived():
            derived_n += 1           # marked-but-not-measured → not in the distribution (discipline)
        else:                         # QUARANTINED
            quarantined_n += 1
    total = len(group)
    coverage = (measured_n / total) if total else 0.0
    value = {
        "distribution": distribution, "measured_n": measured_n, "derived_n": derived_n,
        "open_n": open_n, "quarantined_n": quarantined_n, "total": total, "coverage": round(coverage, 4),
    }
    if measured_n == 0:
        # no measured CWE at all → the element-CWE is entirely OPEN (no fabrication)
        return Attribute.of_open("aggregate", when, f"{total} CVEs, none with a measured CWE")
    # the distribution over the measured subset IS a real measurement; the OPEN-fraction is carried honestly in value
    return Attribute.of_measured(value, "aggregate", when,
                                 f"CWE-distribution over measured subset; coverage={coverage:.2f} ({measured_n}/{total}), open={open_n}")


def merge_refs(group: list[MergedRecord], when: str) -> Attribute:
    """Union an element's CVE refs. If at least one MEASURED refs exists → MEASURED; else OPEN."""
    merged: list = []
    any_measured = False
    for r in group:
        a = r.refs
        if a.is_measured() and a.value:
            any_measured = True
            for x in a.value:
                if x not in merged:
                    merged.append(x)
    if not any_measured:
        return Attribute.of_open("aggregate", when, "no CVE had measured refs")
    return Attribute.of_measured(merged, "aggregate", when, f"union-refs from {len(group)} CVEs ({len(merged)})")


def aggregate_zone(group: list[MergedRecord], when: str) -> Attribute:
    """
    Element-level realization-zone. Rule: if AT LEAST ONE reachable-CVE → element REACHABLE (machine-#Ç4 at
    least partially possible); no-reachable-but-hardware → HARDWARE (cold zone); none classified → OPEN.
    Counts in value (audit).
    """
    reachable_n = hardware_n = open_n = 0
    for r in group:
        value = r.zone.value_or(None)   # MEASURED/DERIVED → value; OPEN/QUARANTINED → None (indeterminate)
        if value is Zone.REACHABLE:
            reachable_n += 1
        elif value is Zone.HARDWARE:
            hardware_n += 1
        else:
            open_n += 1
    counts = {"reachable_n": reachable_n, "hardware_n": hardware_n, "indeterminate_n": open_n}
    if reachable_n > 0:
        return Attribute.of_measured(Zone.REACHABLE, "aggregate", when,
                                     f"at-least-one reachable (machine-#Ç4 partially); {counts}")
    if hardware_n > 0:
        return Attribute.of_measured(Zone.HARDWARE, "aggregate", when, f"all hardware/indeterminate (cold zone); {counts}")
    return Attribute.of_open("aggregate", when, f"no CVE has a zone classification; {counts}")


def aggregate(records: list[MergedRecord], when: str) -> list[SurfaceElement]:
    """
    Group per-CVE MergedRecords by (subsystem, domain) and aggregate into SurfaceElements.
    The subsystem-anchor must be MEASURED (else the element cannot be built — the CVE is skipped, HONESTLY;
    its count is reported by the caller).
    """
    groups: dict[tuple, list[MergedRecord]] = {}
    anchorless = 0
    for r in records:
        a = r.field("subsystem")
        subsystem = a.value if (a and a.is_measured()) else None
        if not subsystem:
            anchorless += 1          # no subsystem-anchor → no surface-element can be built (no fabrication)
            continue
        groups.setdefault((subsystem, r.domain), []).append(r)

    elements: list[SurfaceElement] = []
    for (subsystem, domain), group in groups.items():
        elements.append(SurfaceElement(
            key=(subsystem, domain), subsystem=subsystem, domain=domain,
            cve_keys=[r.key for r in group], cve_count=len(group),
            cwe=aggregate_cwe(group, when),
            refs=merge_refs(group, when),
            zone=aggregate_zone(group, when),
            is_interface=_is_interface(subsystem),
        ))
    # anchorless count may be needed by the caller; for now return elements (reported separately in the fetcher)
    return elements
