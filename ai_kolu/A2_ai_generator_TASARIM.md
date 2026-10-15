# A2 — AI-GENERATOR (discovery + sense-making + attack-path generation) — DESIGN SKELETON

> Phase: AI-arm build-decompose · Module: A2 (on top of the A1 substrate) · Status: DESIGN (NOT code).
> Basis: İ1-İ9 (`PoC_BULGULAR.md` §AI ARM ARCHITECTURE) + §VISION (multi-lens discovery). A1 is ready: population +
> realization-detector + ledger + adapter-bridge. A2 = the arm that PRODUCES predictions (the ledger fills once A2 arrives).

## 0. What A2 does (one sentence)
It turns the surfaces the core has budgeted into type-2 predictions (a stress-point + an attack-path link)
via **multi-lens discovery**; every output is OPERATIONAL + FALSIFIABLE + status-labeled. Philosophy DISCOVERS, reality JUDGES.

## 1. Sub-decompose (A2.1–A2.5)

- **A2.1 — Attention-intake (the energy-governor interface).** Consumes the core's D/tier decision → a work-list
  `(surface, budget)`. **skip → do not touch at all** (the core is the AI's energy-governor, VISION). Strategic → full-power.
- **A2.2 — Multi-lens discovery engine.** Look at each budgeted surface through MANY lenses (philosophical/sociological/historical/
  psychological/epistemic) → candidate stress-points. A lens = a VIEWPOINT (internal), not an output. The LLM-operator is here.
- **A2.3 — Operational-projection / BOUNDARY (the epistemic red-line).** Candidate → a TYPED falsifiable operational
  stress-point; **the lens-narrative is DISCARDED here (the lens dies at the boundary, VISION).** A candidate that
  cannot be cast into a testable-claim is REJECTED. This module is the barrier that prevents the vision from collapsing.
- **A2.4 — Attack-path assembly.** Stress-points → a status-labeled chain (İ2): type-1 (measured) + type-2
  (prediction) links mixed; two directions (İ4: surface→forward discovery, target→backward operation).
- **A2.5 — Publication to the ledger.** Each type-2 → `dolum.record_prediction` (exposure/horizon/tier_at_creation assigned).
  Connects to the detector + #Ç4 line.

## 2. Critical constraints / design-tensions

**K1 — A2 IS EXPOSURE-BLIND (critical, otherwise the control-group collapses).** A2 produces a prediction for EVERY surface the core
has budgeted — **for held-out surfaces TOO, at full budget.** Exposure is assigned downstream (`dolum`), A2 does not see it.
Otherwise there are no predictions on held-out → the clean-baseline is EMPTY → #Ç4 cannot measure. The held-out veil is
applied in PRESENTATION, not in PRODUCTION. (A held-out strategic surface = "what would the AI have predicted here, did reality confirm it — with no one acting?" a pure signal.)

**K2 — BOUNDARY leak-tightness (the VISION red-line).** The output is forced through a TYPED schema: a stress-point passes only if
it can be expressed as `(surface, predicted-vulnerability-class, testable-signal, mechanism)`.
Sociological/philosophical free-text CANNOT PASS the schema (a structural obstacle). Untestable → reject. "The lens said where to look;
the output is what you found, not why."

**K3 — Energy-governor mapping.** tier/D → (how-many-lenses + reasoning-depth). strategic = all lenses+deep;
tactical = a lens subset/shallow; skip = skip. The mapping is a CHOSEN-parameter (like A1's f/horizon).

**K4 — Multi-lens = PARTIAL-diversity (MODERATE-K4, the 2026-07-17 decision — strong-K4 REJECTED).**
In İ6 it had been proposed that "separate-lens = operator-diversity"; the researcher rightly CORRECTED it:
- Multi-lens on the SAME model does NOT GIVE REAL operator-diversity. Systematic bias lives in the WEIGHTS;
  a lens changes the PROMPT/framing, not the weights. 5 lenses = 5 frames, 1 weight-set → all inherit the same
  deep blind-spot. Agreement across lenses is CORRELATED (shared weights).
- Strong-K4 (trusting corroboration) = the error of mistaking-correlated-votes-for-independent → FALSE-CONFIDENCE → the laundering
  of a robust-echo in the guise of "diversity" (it makes the eye more-confidently-wrong).
- **Moderate-K4:** lens-corroboration = at most a correlation-discounted **weak within-discovery priority-prior**
  (which type-2 is presented first), NEVER a confirmation, ABOVE the gate. REAL robustness = NOT lens-vs-lens, but
  **lens-vs-REALITY**: provenance + #Ç4 per-lens hit-rate (an independent arbiter=reality, not a correlated peer).
- The REAL gain of multi-lens = discovery breadth (it breaks the frame-lock, closes blind-spots) — this is sound.
  Real operator-diversity (different MODELS) remains open to the FUTURE as a robust-echo defense; this mechanism is not that.

## 3. DECISIONS (✅ decided 2026-07-17)

1. **Lens-set = an EXTENSIBLE registry (not fixed).** Start: the 5 of the VISION (philosophical/sociological/
   historical/psychological/epistemic) **+ "technical" (the base-lens** — most stress-points are still technical). Extensible
   because #Ç4 will over time show which-lens-is-accurate → add new ones / remove the weak. A fixed-set would prevent this.
2. **Lens-application = a SEPARATE pass per-lens** (for cleanliness + provenance), BUT with the **MODERATE-K4** reading:
   the separate-pass is NOT FOR corroboration-confidence (that is false, K4); it is for discovery-cleanliness + per-lens measurement. Real
   robustness is lens-vs-reality (#Ç4), not lens-vs-lens.
3. **Boundary-schema = 5 fields + a measurement-category:** `(surface, vulnerability-class, testable-signal, mechanism,
   SOURCE-LENS)` + `measurement-category` (1=now / 2=pending-detector). Refinements (A2m23 §5):
   - `vulnerability-class` = **the v0-ruler CWE-families, a CLOSED-SET** (not free-text → tight boundary + measurement-cleanliness + v0-consistency).
   - `testable-signal` = **a falsification-method** (first-class, auditable); the THREE-WAY criterion: is-the-method-defined
     (now→cat.1, concrete-future→cat.2 pending-detector, undefined→REJECT). A cat-2 method must be LIMITED+DISTINCTIVE (the guards).
   - the 5th field = provenance (MANDATORY for K4-moderate: without it #Ç4 cannot measure per-lens hit + cat-2-rate).
   Philosophical-free-text still cannot pass (the structural obstacle is preserved).
4. **Energy-mapping = CHOSEN (DECLARATION, not calibration — like v0).** strategic→all lenses+deep ·
   tactical→few lenses+medium · skip→none. Declared up front; later revisable via #Ç4 but CHOSEN-labeled.
5. **Prediction-unit = SINGLE-anchor on the SOURCE-surface.** A path-link spans 2 surfaces → it is anchored to the
   **(source) surface where the prediction STARTED** (NOT the target). Single-anchor because double-anchor DOUBLE-COUNTS the same-path in #Ç4.
6. **The first detail = A2.2+A2.3 TOGETHER** — inseparable: the lens free-generates (A2.2), the boundary forces-to-operational
   (A2.3); if designed separately either philosophy-leaks (the boundary is weak) or discovery-is-choked (the boundary too-tight). → `A2m23_*_TASARIM.md`.

## 4. Boundaries (invariant)
Do not touch the core · Prozessfall read-only · one-way (ai_kolu→adapter→cekirdek) · every prediction starts type-2
(a status-less path is forbidden) · feeding only type-1 (İ3) · output 100% operational-falsifiable (the lens does not leak into the output).
NOTE: in the A2-BUILD the LLM-operator = the newest Claude; when the code round begins the claude-api reference will be read (now it is design).
