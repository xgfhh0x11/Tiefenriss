# A1 module-2 — LEDGER-POPULATION + HELD-OUT ASSIGNMENT — DESIGN

> Phase: AI-arm build-decompose · Module: the second of A1 · Status: DESIGN (NOT code).
> Principle-basis: İ7 (self-fulfilling / held-out) + #Ç4. Linked: `A1_realization_detector_TASARIM.md`
> (the detector's exposure-label connects here), `ongoru_defteri.py` (schema).

## 1. Responsibility

The WRITE-PATH of the prediction-ledger + the creation-moment field-assignments. When a type-2 prediction is recorded:
- **exposure** is assigned (HIGHLIGHTED / HELD_OUT) — at CREATION, immutable (İ7 leak-tightness).
- a **tier_at_creation** snapshot is taken (the adapter pipeline's current core-tier for that surface;
  for the realization-detector's params-drift-free comparison).
- **horizon_days** is assigned (a per-direction CHOSEN default).
What it does NOT do: it does NOT PRODUCE predictions (that is the A2 AI-generator). This module is the record-infrastructure; EMPTY in production until A2 arrives.
It is set up on Day-1 (İ7: the clean-baseline effectively begins here).

## 2. Held-out assignment = SEEDED-RANDOM (the 2026-07-16 decision)

**Why random (NOT structural):** held-out being the gold-standard-baseline depends on it being a representative-unbiased
sample from the SAME population as highlighted — the only difference being exposure (an RCT control-group). Randomization
makes the counterfactual valid. Structural assignment → a biased sub-population → `excess` conflates the exposure-effect
with the population-difference → the clean-reference COLLAPSES. (See #Ç4 asymmetry: held-out=baseline, highlighted=deviation.)

**Mechanism:** `held_out ⟺ stable_hash(unit_id + SEED) mod 10000 < f·10000`.
- deterministic + **fixed-recorded SEED** → reproducible (independent of machine/rerun, auditable).
- at CREATION, before the outcome is known → blind. INDEPENDENT of surface-features (NO stratification — splitting by
  any surface-covariate brings structurality back; pure-random is the default).

## 3. ASSIGNMENT-UNIT = SURFACE (refinement — critical)

If exposure is assigned per-prediction, the same surface could have one held-out + one highlighted prediction →
the highlighted-sibling draws attention to the surface → the held-out prediction is no longer attention-free → the baseline is contaminated.
→ **Assignment-unit is SURFACE:** a held-out surface = no prediction about it is shown to the user → pure
reality is preserved. `unit_id = surface_id` (not prediction_id). All of a surface's predictions inherit its
exposure.
**Product-cost:** the tool stays silent on held-out surfaces (the cost of the control-group) → `f` is a CHOSEN-tradeoff
(large f = a tight baseline-estimate but more silence; small f = less silence but a noisy baseline).

## 4. Leak-tightness (İ7, already in the schema)
`user_visible()` does NOT RETURN held_out · `route_to_user()` rejects held_out · exposure is immutable.
Module-2 USES these; it does not violate them. The held-out assignment-table (surface→exposure) is persistent + immutable.

## 5. DECISIONS (✅ sealed 2026-07-16)
- ✅ Assignment = seeded-random (not structural).
- ✅ Unit = surface (refinement; for an attention-free baseline).
- ✅ **f = 15% (CHOSEN).** Band 10-20%, the middle. **The real risk is a small-f:** if held-out is too small the base-rate rests on a few
  surfaces → Poisson-noise (the same trap as the KEV 11-CVE underpowered case). 15% is a sufficient sample for the baseline
  even in the few-users phase. The "tool silent" cost of a large-f is negligible in A-mode (personal radar).
  **NOTE (live):** check whether held-out-N is sufficient; if the baseline is noisy, INCREASE f.
- ✅ **SEED = a single global fixed-seed, persisted into the ledger-config.** **IMMUTABILITY IS AN INVARIANT, NOT a config-value:**
  if the seed changes the held-out/highlighted assignment shifts entirely → the clean-baseline accumulated up to that moment
  is INVALIDATED (the İ7 clean-baseline window collapses). It is written into the config marked "NEVER CHANGE; if changed the baseline resets."
- ⏳ **#Ç4 refinement (second-order, DEFERRED, does not block):** to turn held-out from a self-fulfilling-meter into a SKILL-meter
  the NON-predicted surface base-rate is needed (held-out-predicted vs never-predicted surface →
  "does prediction beat random"). Not in the ledger but in the surface-universe; #Ç4-second-round.

## 6. BUILD STATUS
✅ **A1-BUILD DONE (2026-07-16):** `defter_config.py` (f=0.15 CHOSEN, SEED invariant, direction-horizons) +
`dolum.py` (`assign_exposure` surface-unit sha256 seeded-random; `record_prediction` exposure+horizon+
tier_at_creation). Test `test_a1.py` 7/7 (held-out fraction measured at 0.150; same-surface→same-exposure verified).
The production ledger is EMPTY (there is no A2 producing predictions). Next: A2 (AI-generator) → the ledger fills → #Ç4 longitudinal begins.
