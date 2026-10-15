"""
status.py — STATUS MACHINE (record level). The data-layer extension of the core's §11 edge-status
machine (A/B/C = MEASURED/DERIVED/PRODUCED + quarantine).

╔══════════════════════════════════════════════════════════════════════════╗
║ CORE PRINCIPLE — status is INSEPARABLE from data:                          ║
║   Every field is an `Attribute` = value + epistemic-status + provenance +  ║
║   HISTORY. Status/provenance CANNOT be retrofitted (if not captured at     ║
║   production time it is lost) → hence #1, before everything.               ║
╚══════════════════════════════════════════════════════════════════════════╝

Principles carried (`veri/TASARIM.md`, `adapter/PoC_BULGULAR.md`):
  • OPEN ≠ null — "we don't know, we do NOT force". Downstream must not treat OPEN as measured
    (else the "leave-open" principle collapses). Barrier: `measured()` returns only when MEASURED.
  • Status is EVOLVABLE — the data-layer form of the time-gate (tip2→tip1, İ5). `evolve()` writes the
    transition to `history` (when/which-status/why). Timestamps caller-supplied (no embedded now()).
  • Ported to Rust, this barrier becomes compile-time enforcement (the real Rust value).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class DisciplineError(Exception):
    """Status-discipline violation (e.g. an OPEN/QUARANTINED value requested as if 'measured'). Code-level barrier."""


# ---------------------------------------------------------------------------
# STATUS — evolvable epistemic state (fixed vocabulary)
# ---------------------------------------------------------------------------
class Status(str, Enum):
    """
    Epistemic state of a record field. The data-layer form of the core status machine.
      MEASURED    (measured)   — read mechanically from source, NO judgement. Trusted value (only `measured()` returns it).
      DERIVED     (derived)    — produced by threshold/embedding (visible-political). Marked value, NOT measured.
      OPEN        (open)       — deliberately empty: we don't know, we do NOT force. value=None but NOT null (status distinguishes).
      QUARANTINED (quarantine) — measured BUT suspect (audit-bias / unverifiable). Has a value, not trustworthy.
    """
    MEASURED = "measured"
    DERIVED = "derived"
    OPEN = "open"
    QUARANTINED = "quarantined"


# Trust order for join/conflict: a measured value FILLS an open one (higher wins).
TRUST_ORDER: dict[Status, int] = {
    Status.MEASURED: 3,
    Status.DERIVED: 2,
    Status.QUARANTINED: 1,
    Status.OPEN: 0,
}


# ---------------------------------------------------------------------------
# STATUS TRANSITION — a single transition (the atom of the evolution trail)
# ---------------------------------------------------------------------------
@dataclass
class StatusTransition:
    """A status transition. `history` is a sequence of these; [0]=creation, [-1]=current. Time caller-supplied."""
    status: Status
    when: str            # ISO or day-str; caller-supplied (no embedded now() → deterministic)
    source: str          # provenance — which source/method set this status
    reason: str = ""     # why this status / this transition (auditability)


# ---------------------------------------------------------------------------
# ATTRIBUTE — value + status + provenance + evolution history
# ---------------------------------------------------------------------------
@dataclass
class Attribute:
    """
    A status-typed single field. Canonical creation via factory methods (`of_measured`/`of_derived`/
    `of_open`/`of_quarantined`) — all require provenance (no attribute without a source). `history` is
    seeded at creation.

    Disciplined access:
      measured()          → value, ONLY if MEASURED; otherwise DisciplineError (the main barrier).
      quarantined_value() → value, ONLY if QUARANTINED ("I knowingly want the suspect value").
      value_or(default)   → value if MEASURED/DERIVED, otherwise default (OPEN/QUARANTINED → default).
    Direct access to the raw `value` field BYPASSES discipline — the legitimate path is the methods above.
    """
    value: object | None
    status: Status
    provenance: str
    history: list[StatusTransition] = field(default_factory=list)

    # --- canonical factories (provenance required) ---
    @classmethod
    def of_measured(cls, value, source: str, when: str, reason: str = "") -> "Attribute":
        t = StatusTransition(Status.MEASURED, when, source, reason or "measured-from-source")
        return cls(value=value, status=Status.MEASURED, provenance=source, history=[t])

    @classmethod
    def of_derived(cls, value, source: str, when: str, reason: str = "") -> "Attribute":
        t = StatusTransition(Status.DERIVED, when, source, reason or "derived")
        return cls(value=value, status=Status.DERIVED, provenance=source, history=[t])

    @classmethod
    def of_open(cls, source: str, when: str, reason: str = "") -> "Attribute":
        # OPEN ≠ null: value None but the status carries deliberate emptiness. NO fabrication.
        t = StatusTransition(Status.OPEN, when, source, reason or "no-derivation, left-open")
        return cls(value=None, status=Status.OPEN, provenance=source, history=[t])

    @classmethod
    def of_quarantined(cls, value, source: str, when: str, reason: str = "") -> "Attribute":
        t = StatusTransition(Status.QUARANTINED, when, source, reason or "measured-but-suspect")
        return cls(value=value, status=Status.QUARANTINED, provenance=source, history=[t])

    # --- disciplined access (barriers) ---
    def measured(self):
        """MAIN BARRIER: return the value only if MEASURED. OPEN/DERIVED/QUARANTINED → DisciplineError."""
        if self.status is not Status.MEASURED:
            raise DisciplineError(
                f"field '{self.provenance}' status={self.status.value} — cannot be requested as 'measured' "
                f"(OPEN≠null; leave-open principle). Use value_or()/quarantined_value() or handle the status."
            )
        return self.value

    def quarantined_value(self):
        """Knowingly-suspect access: return the value only if QUARANTINED (else wrong-method → error)."""
        if self.status is not Status.QUARANTINED:
            raise DisciplineError(f"quarantined_value() only on QUARANTINED; here status={self.status.value}.")
        return self.value

    def value_or(self, default):
        """value if MEASURED/DERIVED (usable-marked), otherwise default (OPEN/QUARANTINED)."""
        return self.value if self.status in (Status.MEASURED, Status.DERIVED) else default

    # --- predicates ---
    def is_measured(self) -> bool: return self.status is Status.MEASURED
    def is_derived(self) -> bool: return self.status is Status.DERIVED
    def is_open(self) -> bool: return self.status is Status.OPEN
    def is_quarantined(self) -> bool: return self.status is Status.QUARANTINED

    # --- evolution (the data-layer form of the time-gate) ---
    def evolve(self, new_status: Status, value, source: str, when: str, reason: str = "") -> "Attribute":
        """
        Status transition: OPEN→MEASURED (NVD-backlog filled) / QUARANTINED→MEASURED (verified), etc.
        WRITES the transition to `history` (permanent trail), updates current value/status/provenance. Records are NOT deleted.
        """
        self.history.append(StatusTransition(new_status, when, source, reason or f"{self.status.value}→{new_status.value}"))
        self.value = value
        self.status = new_status
        self.provenance = source
        return self

    def as_dict(self) -> dict:
        """JSON-able view (persistence/audit). Status + history preserved."""
        return {
            "value": self.value,
            "status": self.status.value,
            "provenance": self.provenance,
            "history": [{"status": t.status.value, "when": t.when, "source": t.source, "reason": t.reason}
                        for t in self.history],
        }

    def __repr__(self) -> str:
        return f"Attribute({self.status.value}, value={self.value!r}, prov={self.provenance!r})"
