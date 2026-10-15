"""
cekirdek/types.py
==================
The core's fundamental data types.

Design principle: ELEMENT-AGNOSTIC.
The core does not know WHAT an element IS (a CVE, a config, an architectural node —
it does not care). It sees only the element's three-dimensional PROFILE:
    - value   (v)  : comes from the graph-position  [not-space, relational position]
    - persistence (π)  : comes from the signal history [time axis]
    - spread  (ρ)  : in how many separate places it appeared  [space axis]

The core takes this profile and returns a PROCESSING-DEPTH (D).
"Is this profile correct?" is NOT the core's question, it is the adaptation/validation layer's job.
The core: garbage in → garbage out. The boundary is named, not hidden. (v2.1 §14.D)

Reference: cekirdek_formalizasyon_v2_1.md
"""

from __future__ import annotations
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# SIGNAL — the raw input of persistence (π)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Signal:
    """
    A single signal pulse. σ_bin is BINARY (v2.1 K3):
    "did a signal arrive?" → yes. NO weight — intensity lives in v, repetition in π,
    σ stays binary so the two do not mix.

    t : the time the signal arrived (absolute, unit: days by default).
        The core counts time abstractly; whether "day" or "hour" is a calibration (λ) matter.
    """
    t: float  # the signal's time (τ)
    # NOTE: deliberately NO 'strength/severity' field. σ is binary.


# ---------------------------------------------------------------------------
# GRAPH-POSITION — the raw input of value (v)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class GraphPosition:
    """
    The element's position in the graph. Value is not INTRINSIC, it is RELATIONAL (v2.1 §11, Pressure 3).
    PageRank logic: we are not judging the element's "quality", we are measuring its POSITION.

    v = v0 * (g_A + w * g_B)   — composite gate, mixed-status (v2.1 §1)

    g_A : position from Type A edges (same CPE/CWE/file/patch-cycle).
          MEASURED. Pure measurement, no judgment.
    g_B : position from Type B edges (embedding similarity, threshold 0.80).
          DERIVED. Thresholded, auditable.

    Type C edges (exploit-chain judgment) NEVER ENTER HERE (v2.1 §11).
    If C enters, judgment is inserted into the gate → K4 + quarantine violation.
    This type has no C field — made architecturally impossible.
    """
    g_A: float  # measured graph-position (Type A), [0,1] expected
    g_B: float  # derived graph-position (Type B, thresholded), [0,1] expected
    # NOTE: deliberately NO 'g_C' field. Type C cannot enter the core.


# ---------------------------------------------------------------------------
# ELEMENT PROFILE — the core's ONLY input
# ---------------------------------------------------------------------------
@dataclass
class ElementProfile:
    """
    The full profile an element presents to the core. Whatever the element is
    (CVE, config, architectural node, environment piece) it reduces to this profile.
    The core sees nothing beyond it.

    v0            : static value-ruler (epistemic-infrastructure, fixed). [0,1]
                    "intrinsic value base" — CWE weight etc. A ruler, does not move.
    graph_pos     : graph-position (g_A, g_B) — the relational part of value.
    signals       : signal history — the raw input of persistence (π).
    spread_count  : raw input of spread (ρ) — in how many SEPARATE places/subsystems the
                    element appeared. NOT repetition (π) — that is time, this is space. (v2.1 Pressure 2)

    element_id    : for tracking/reporting only. The core DOES NOT CONSIDER it.
    """
    v0: float
    graph_pos: GraphPosition
    signals: list[Signal] = field(default_factory=list)
    spread_count: int = 0
    element_id: str = ""  # opaque label; the core does not look at its content


# ---------------------------------------------------------------------------
# CORE OUTPUT — processing-depth decision
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DepthDecision:
    """
    The core's output: how much processing-depth to allocate to this element.

    depth   : D(s,t) — continuous value [0, D_max]. "How deep to look."
    tier    : the interpreted layer — derived for readability only,
              NOT the core's decision but a label. (taktik/stratejik/atla)
              The real distinction is continuous (depth); tier is coarsening for human reading.

    Intermediate values (for transparency — not a black box):
    tension : G(s,t) tension
    value   : v = v0*(g_A + w*g_B) computed value (gate)
    persistence : π persistence
    spread  : ρ spread (normalized)
    """
    depth: float
    tier: str  # "atla" | "taktik" | "stratejik"
    tension: float
    value: float
    persistence: float
    spread: float
