"""
Tiefenriss — ADAPTER layer.

Converts the raw element (CVEs in the Prozessfall SQLite) into the core's profile
(ElementProfile). The core does not know WHAT the element is; the adapter's job is to
reduce it to three abstract signals: value (v0, graph-position) + persistence (signals) +
spread (spread_count).

DEPENDENCY DIRECTION IS ONE-WAY: the adapter imports the core (via core_bridge),
the core NEVER imports the adapter. The core stays isolated and element-agnostic.

EPISTEMIC DISCIPLINE (flagged for every value):
    MEASURED  — mechanical from data (Type A: shared CWE/CPE)  → g_A, signals, spread
    DERIVED   — model + threshold (Type B: embedding sim ≥ 0.80) → g_B
    CHOSEN    — political/design decision (NOT a measurement)   → v0 ruler, g_A edge weights
Type C (exploit-chain judgment) enters nowhere — there is no g_C in GraphPosition.

SCOPE (this PoC): only CPE-CLEAN surfaces (subsystem = CPE vendor:product).
Subsystems guessed from description text are NOT MIXED IN (separate, later work) —
otherwise part of g_A would be measured and part guessed, and they could not be separated.
"""
