# A2.2 + A2.3 — MULTI-LENS DISCOVERY + BOUNDARY — DESIGN

> Phase: the first detail-module of A2 (AI-generator) · Status: DESIGN (NOT code).
> Basis: `A2_ai_generator_TASARIM.md` (decisions §3, MODERATE-K4 §2-K4) + §VISION. A2.2 and A2.3 are INSEPARABLE:
> the lens free-generates, the boundary forces-to-operational; if they do not work together either philosophy-leaks or discovery-is-choked.

## 1. Flow (for one surface)
`(surface, budget)` [from A2.1] → **A2.2** an LLM-pass per lens → candidate stress-points (lens-labeled) →
**A2.3** PROJECT each candidate into the 5-field typed schema + a falsifiability-gate → those that pass = type-2 stress-points;
those that do not = reject (logged). → A2.4 assembly / A2.5 publication to the ledger.

## 2. A2.2 — the multi-lens engine

- **Lens = viewpoint-framing** (role/system-prompt): it steers HOW the surface is looked at. INTERNAL —
  not an output (VISION). The lens reasons freely (A2.2 is PERMISSIVE so that discovery is broad).
- **A separate pass per-lens** (decision §3.2): each lens produces its own candidates, labeled with `source-lens`.
  MODERATE-K4: the separate-pass is for cleanliness+provenance, NOT for corroboration-confidence.
- **Lens-definition = data (an extensible registry, decision §3.1).** A lens: `{name, viewpoint-prompt,
  is-active}`. The starting 6: technical(base) + philosophical/sociological/historical/psychological/epistemic. The prompt-contents
  are written in the BUILD (here is the schema). #Ç4 deactivates a weak-lens / adds new ones.
- **Input context:** the surface's adapter-data (member CVEs, CWE, product, structural/semantic neighborhood). Read-only.
- **Budget (energy-governor):** how many lenses + depth, from the tier (decision §3.4). skip → A2.2 does not run at all.

## 3. A2.3 — BOUNDARY (the vision's red-line)

**The 5-field typed schema (decision §3.3):** `(surface, vulnerability-class, testable-signal, mechanism, source-lens)`.
A free-text narrative does NOT FIT here → the lens dies at the boundary. If a candidate cannot be cast into this schema it is REJECTED.

**THE CENTRAL PRINCIPLE — the boundary tests FALSIFIABILITY, not CONVENTIONALITY.**
This is the setting that resolves the "boundary-weak→philosophy-leaks / boundary-tight→discovery-choked" tension:
- A novel stress-point (from a historical/psychological lens) PASSES — if it can name a `testable-signal`,
  even if it is unusual.
- It is REJECTED — only if it can name no controllable outcome at all ("reflects institutional-negligence" →
  no signal → philosophy → reject).
- That is, the filter is "IS THERE a signal in reality that will confirm/refute this?" — NOT "does it look technical?".
  Novel-but-testable is preserved; untestable-but-deep is discarded. **The `testable-signal` field = the boundary itself:
  if you can fill it you pass, if you cannot you are philosophy.**

**How `testable-signal` connects to reality (the bridge to A1):** the signal must be reducible to something the
time-gate can measure. TODAY'S minimum measurable signal = the anchor-surface's **core-tier-crossing**
(realization-detector, A1). Finer signals (a specific primitive in a specific subsystem) are a live-detector-
refinement. → the signal must be at least as concrete as "this surface's tier will rise"; otherwise it is un-measurable.

**Reject-logging (transparency + lens-quality signal):** rejected candidates are NOT DELETED, they are logged with `source-lens`.
The REJECT-RATE per-lens = a measure of how much untestable-noise that lens produces → the second face of #Ç4-per-lens
(hit-rate + reject-rate together = lens-quality). NO silent-discard (the blind-spot is not hidden).

## 4. Why A2.2+A2.3 together (inseparability)
A2.2 is permissive (discovery broad), A2.3 is strict-but-via-falsifiability (discipline). The calibration is in the
BALANCE of the two: A2.2 alone → philosophy-leaks; A2.3 alone (by conventionality) → discovery-choked. The right
point: free-generate + a falsifiability-gate. This is why they were designed together.

## 5. DECISIONS (✅ sealed 2026-07-17)

1. **`testable-signal` = THREE-WAY (criterion: NOT "measurable-now", but "a FALSIFICATION-METHOD IS DEFINABLE" — Popper).**
   - **measurable-now** (reduces to tier-crossing) → enters the time-gate (category-1).
   - **unmeasurable-now but a concrete-future-measurement-is-defined** → the `pending-detector` queue; tested once that detector is built (category-2).
   - **measurement-undefined** (the AI says "trust me") → REJECT, the philosophy-category (category-3).
   Why loose is dangerous: the AI decides on "true-in-principle-but-unmeasurable" → it exempts its own-prediction from measurement →
   forever "awaiting-detector" → never falsified = an echo-chamber. The escape-hatch is closed BY THE CRITERION: a prior COMMITMENT
   to a falsification-method (an auditable debt), not an exemption.
   **THREE GUARDS (fully sealing the escape-hatch):**
   - (a) a category-2 method must be LIMITED+DISTINCTIVE, not merely "concrete" (naming a horizonless-detector =
     a hidden category-3; the same as A1's LAPSED-horizon → the pending-detector record carries feasibility/horizon).
   - (b) the falsification-method is recorded as a FIRST-CLASS FIELD (it externalizes the AI's acceptance-judgment into an auditable spec).
   - (c) the category-2 RATE is tracked per-lens (a #Ç4 extension): a lens that disproportionately escapes to "measurable-one-day",
     even if its individual-predictions look "concrete", is an escape-hatch at the population-level → a second-order guard.
   → SCHEMA UPDATE: the `testable-signal` field carries the falsification-method + a `measurement-category` (1/2) label is added.
2. **Lens-definition schema = `{name, viewpoint-prompt, is-active, budget-priority}`.** Priority is needed because a tactical-surface
   gets "few lenses" → which ones? Priority gives that ordering; revised via #Ç4.
3. **Reject-log = a structured-summary + a reject-reason (which-field-was-empty: signal or mechanism).** A count-only is not enough
   (you cannot see what was rejected), full-text is expensive. The middle ground: whether the lens is BAD or the PROMPT is bad can only be told from a content-summary.
4. **Vulnerability-class = the v0-ruler CWE-families, a CLOSED-SET** (NOT free-text). A tighter boundary + measurement-cleanliness +
   v0-consistency. Extensible but set-membership is CONTROLLED (not free-text).

## 6. Boundaries (invariant)
Output 100% operational-falsifiable (the lens does not leak into the output) · every stress-point starts type-2 · A2 is exposure-
blind (it produces for held-out too) · do not touch the core · read-only · one-way. The LLM-operator in the BUILD = the newest Claude.
