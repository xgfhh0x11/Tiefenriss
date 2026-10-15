"""
merge.py — JOIN/enrichment layer, status-PRESERVING (first-class).

A surface does not come from one source: kernel-git(subsystem+commit) ⋈ NVD(CWE) on `cve_id`.
Sources produce PARTIAL status-typed records; this builds the full per-CVE MergedRecord status-preservingly.

On field conflict, TRUST-ORDER (status.TRUST_ORDER): MEASURED > DERIVED > QUARANTINED > OPEN.
  → a measured value FILLS an open one = an OPEN→MEASURED promotion at join, written to HISTORY (auditable).
If no source provides a canonical field → OPEN (NOT null; "leave-open" preserved).
"""
from __future__ import annotations

from .status import Attribute, Status, StatusTransition, TRUST_ORDER
from .record import MergedRecord, PartialSurface


# Statuses that may FILL an OPEN field (decision-b, 2026-07-19): only measured/derived. QUARANTINED (suspect,
# value-carrying-but-gated) does NOT override the deliberate abstention (OPEN) — "we truly don't know" ≠ "something suspect".
FILLERS = (Status.MEASURED, Status.DERIVED)

# Fields that must ALWAYS exist on a record. If no source provides one → OPEN-filled (not a null-gap).
# refs/zone are handled separately (first-class, below).
CANONICAL_FIELDS = ("subsystem", "cwe")


def _merge_field(current: Attribute, incoming: Attribute, when: str) -> Attribute:
    """
    Pick the winner of two attributes. OPEN-STICKINESS (decision-b): an OPEN field is filled ONLY by
    MEASURED/DERIVED; QUARANTINED cannot override it (even though TRUST_ORDER puts QUARANTINED>OPEN). The
    fill-promotion (OPEN→measured/derived) is written to history (the join form of the time-gate).
    """
    if TRUST_ORDER[incoming.status] > TRUST_ORDER[current.status]:
        winner, loser = incoming, current
    else:
        winner, loser = current, incoming

    # OPEN-stickiness: loser is OPEN but winner is NOT a FILLER (QUARANTINED) → KEEP OPEN (don't override).
    if loser.status is Status.OPEN and winner.status not in FILLERS:
        return loser

    # a legitimate filler (MEASURED/DERIVED) filled an OPEN → write the promotion to history (auditable)
    if loser.status is Status.OPEN and winner.status in FILLERS:
        winner.history.append(StatusTransition(
            winner.status, when, winner.provenance,
            reason=f"join: was OPEN in '{loser.provenance}', filled by '{winner.provenance}'",
        ))
    return winner


def merge(partials: list[PartialSurface], when: str) -> list[MergedRecord]:
    """
    Group PARTIAL surfaces by `key` (cve_id) and merge status-preservingly into per-CVE MergedRecords.
    `refs`/`zone` are extracted first-class (OPEN if absent). Canonical fields are OPEN-filled if missing.
    (For the surface-ELEMENT call `aggregate()` afterwards — subsystem-keyed aggregation.)
    """
    groups: dict[str, list[PartialSurface]] = {}
    for ps in partials:
        groups.setdefault(ps.key, []).append(ps)

    records: list[MergedRecord] = []
    for key, group in groups.items():
        domain = group[0].domain
        merged: dict[str, Attribute] = {}
        traces: list[str] = []

        for ps in group:
            traces.append(ps.source_name)
            for name, attr in ps.fields.items():
                if name in merged:
                    merged[name] = _merge_field(merged[name], attr, when)
                else:
                    merged[name] = attr

        # refs/zone first-class: split off, OPEN if absent (no fabrication — the census 0-refs lesson)
        refs = merged.pop("refs", None) or Attribute.of_open("join", when, "no source provided refs")
        zone = merged.pop("zone", None) or Attribute.of_open("join", when, "zone not classified")

        # canonical fields missing → OPEN-fill (OPEN ≠ null; downstream must not treat as measured)
        for name in CANONICAL_FIELDS:
            if name not in merged:
                merged[name] = Attribute.of_open("join", when, f"no source provided '{name}'")

        records.append(MergedRecord(
            key=key, domain=domain, fields=merged, refs=refs, zone=zone, source_traces=traces,
        ))
    return records
