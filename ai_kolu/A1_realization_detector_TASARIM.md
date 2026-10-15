# A1 — REALIZATION-DETECTOR (the measurement-heart of the time-gate) — DESIGN

> Phase: AI-arm build-decompose · Module: the first of A1 · Status: DESIGN (NOT code).
> Principle-basis: `PoC_BULGULAR.md` §AI ARM ARCHITECTURE (especially İ5 time-gate, İ7 self-fulfilling,
> #Ç4). This module turns #Ç3 from a ONE-OFF-MEASUREMENT into a PERSISTENT-MECHANISM (just as the ledger
> made #Ç4's control persistent).

## 1. Responsibility (NARROW — deliberately)

The arbiter of the time-gate is REALITY (İ5). The realization-detector is that arbiter's measurement-organ:
**it MEASURES whether pending type-2 predictions have COME TRUE or not, stamps them, and updates the ledger.**

What it DOES: "did the predicted reality-signal occur?" — it measures, time-stamps, exposure-labels.
What it does NOT do: it does NOT render the JUDGMENT "was the prediction accurate?" The skill (precision/base-rate/gap) = #Ç4's job,
downstream. The detector produces raw realization-events; #Ç4 interprets them against the control group.
(The separation is like the core's `value()` returning raw-v and applying the gate separately — a separation of responsibility.)

**DETERMINISTIC — NO AI.** The detector uses measured-signals + CHOSEN-thresholds; "did it come true" is NOT
ASKED to an LLM. This is why it is A1 (the measured substrate), not A2 (the AI generator). The verdict comes from measurement/the core,
not from judgment ("a judge cannot be the defendant" — İ6 CC-flag).

## 2. Position + dependency (invariant)

Inside `ai_kolu/`. Input: the prediction-ledger (pending type-2) + the adapter surface-pipeline (time-sliced).
Output: `promote_to_tip1()` into the ledger (the schema already provides this). ONLY type-1 promotions feed the tight-loop
(the İ3 guarantee). The Prozessfall DB is READ-ONLY; the ledger is its own store. It does not touch the core. One-way is preserved.

## 3. Realization criterion — measurable signals

Prediction content (İ4): `surface→forward` (this surface will become a stress-point) — this is what is MEASURABLE in A1.
(`target→backward` operational realization is hard to measure via CVE-emergence → left to A2/A3.)

**PRIMARY — the core's tier-decision moved upward** (skip→tactical→strategic), AFTER the prediction-stamp.
Why primary: this is the real endpoint of "became a stress-point" AND it uses the core's OWN classification
→ the verdict comes from the core (the arbiter is the correct authority).
- ⚠️ **params-drift trap:** tier thresholds are percentile-anchored and `params.recompute()` shifts as the data grows.
  Did "the tier jumped" come from surface-movement or from threshold-drift? → The comparison must be done against the
  FROZEN snapshot thresholds at prediction-time (or raw G-percentile movement must be measured). Otherwise
  threshold-drift is mistaken for realization (our own #Ç3 reflex: separate the artifact).

**CORROBORATING (supporting, not sufficient on their own):**
- *Pulse-arrival:* did the surface receive new distinct-day pulse(s) after the prediction-stamp — the most robust
  raw reality-signal (direct new CVE arrival).
- *π-rise:* derives from pulses, robust.
- *g-shift:* the correct signal IN PRINCIPLE (value from neighborhood) BUT WEAK in this corpus (#Ç3: mean shift 0.063,
  g_A ~static). → it is logged, LOW-weight; underpowered until multi-year/time-stamped embedding arrives.

**THRESHOLD = the core's CURRENT tier-boundary (the 2026-07-16 decision) — no separate realization-threshold is INVENTED.**
Realization = the surface rose above the core's own tier-boundary, up from `tier_at_creation`. NO new-anchor
(no inventing θ/TAU). Degree (how-many-tiers jumped) is OPTIONAL metadata. The only CHOSEN-param is the realization-horizon
(horizon, below), NOT a realization-threshold. params-drift: the comparison is done on the SAME params-base
(the `tier_at_creation` snapshot) → threshold-shift is not mistaken for realization.

## 4. Asymmetry + ratchet + horizon (İ7/#Ç3: negative ≠ evidence)

- The detector is a RATCHET: on a positive signal → `GERCEKLESTI` (type-1 promotion). "Not yet" = `BEKLIYOR`, **NOT
  FALSE** (not negative evidence — #Ç3). `CURUDU` only on an explicit-measurable dis-confirmation (rare).
- **Realization-horizon:** each prediction receives a horizon at generation (İ5: months). Before the horizon = legitimate `BEKLIYOR`.
  No signal after the horizon = NOT `CURUDU` but `LAPSED` (a third outcome; an over-prediction signal, not a false-refute).
  > Note: `LAPSED` may require a schema-addition (to the Realization enum). Small, evaluated in the A1-build.
- **#Ç4 tie:** the realization-rate is read ONLY over the decided-cases (GERCEKLESTI+CURUDU+LAPSED);
  `BEKLIYOR` does not enter the denominator (otherwise "precision" inflates/collapses).
- **#Ç4 is ASYMMETRIC (the 2026-07-16 clarification) — NOT a symmetric-difference:** held-out = the GOLD-STANDARD BASELINE
  (clean-reference: no attention-effect → pure reality, held-out-LAPSED is a clean negative too). highlighted =
  DEVIATION from the baseline (not a reference; highlighted-LAPSED is ambiguous — either wrong or did-not-draw-attention). The coefficient =
  `excess = highlighted_rate − held_out_baseline` (≥0 = self-fulfilling inflation). The baseline is held-out, highlighted
  is its rise above it. → `confirmation_gap()` was updated accordingly (`held_out_baseline` + `excess`).
  (Refinement: to turn held-out INTO a SKILL, the NON-predicted surface base-rate is additionally needed — not in the ledger
  but in the surface-universe; #Ç4 second-order, does not block module-2.)

## 5. Self-fulfilling tie (İ7 — ends in this module)

The realization-detector is exactly where İ7 BITES: if "a CVE appeared on the surface" = counts as realization AND that CVE
was found BECAUSE it pointed-to-tool-X → the detector endorses the self-fulfilling prophecy. The solution is NOT embedded
in the detector (NO formula-correction — İ9b); the detector merely:
- records each realization-event **exposure-labeled** (highlighted vs held_out — the schema is ready),
- renders no skill-judgment → the highlighted-vs-held_out difference is measured by #Ç4.
That is, the detector does NOT SOLVE self-fulfilling, it makes it MEASURABLE (quarantine, not rescue).

## 6. Two modes

- **Backtest (NOW, underpowered):** time-slice the historical corpus (early→late), look for realization in the late slice.
  The machinery exists (`measure.measure_C3` splits early/late g_A). BUT the #Ç3 limit is inherited: ~6 weeks of firehose +
  bulk-dump → verdicts are weak. The plumbing + interface get validated, the VERDICT is underpowered (honest).
- **Live (when the arm arrives):** the prediction is made NOW, re-measured in the future. The real mode. The İ7-baseline
  begins to accumulate here in the clean-regime → the real payoff of building A1 early.

## 7. DECISIONS (✅ decided 2026-07-16)

1. **Primary criterion → core-tier-crossing.** The verdict comes from the core (clean). ✓
2. **Threshold → the core's CURRENT tier-boundary.** No separate realization-threshold is INVENTED (no new-anchor).
   Degree (how-many-tiers) is OPTIONAL. → schema: a `tier_at_creation` snapshot field (against params-drift).
3. **LAPSED → YES, MANDATORY.** The only source of falsifiability; #Ç4 cannot be measured without it. → schema: `LAPSED`
   added to the Realization enum + a `horizon_days` field + `mark_lapsed()`; PERSISTENT-record (no deletion, only a state-transition).
4. **Horizon → nominal-now, CHOSEN-flagged, percentile-calibrated in live, flexible PER-DIRECTION.** → schema:
   `horizon_days: int | None` (forward≠backward; the caller/detector sets it, NO hardcode in the dataclass).

**IMPLEMENTED (schema):** `ongoru_defteri.py` — LAPSED enum, `horizon_days` + `tier_at_creation` fields,
`mark_lapsed()`, #Ç4 `_rate` includes LAPSED among the decided-cases. The empty-schema was preserved (no population), regression 7/7.
The detector-logic (tier-crossing measurement) is written in the A1-build; for now only the record-interface is ready.

## 8. BUILD STATUS
✅ **A1-BUILD DONE (2026-07-16):** `realization_detector.py` (detect: tier-crossing→promote/lapse,
deterministic, current_tier dependency-injected) + `adapter_bridge.py` (live {sid:tier}). Test `test_a1.py`
7/7, core regression 7/7. The detector-logic is written; the live-loop becomes meaningful once A2 produces predictions (the ledger fills).
Backtest-mode (multi-time-slice) is a live-refinement — deferred because it is #Ç3-underpowered.
Next phase: A2 (AI-generator).
