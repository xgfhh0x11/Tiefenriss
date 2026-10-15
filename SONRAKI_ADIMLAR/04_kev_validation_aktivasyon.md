# 04 — KEV-Validation Activation

**Status:** skeleton ready · **Blocker:** 02 (KEV data) · **Effort:** low

## What / Why

`adapter/validate_kev.py` stands as a skeleton. The goal: v0/g_A is declared **without KEV** →
the system runs → produces high-D surfaces → this output is tested against KEV's **hold-out**
(system-never-seen) truth. The question: **"does the system's attention coincide with the
exploitation truth it has not seen?"** (§12: set up, run, read.)

This is the first **external** evidence of whether the system "works" — not internal consistency.

## How to activate it (once KEV data arrives, 02)

1. Fill in `load_kev(path)`: CISA KEV JSON → `set[cve_id]`. (The TODO in `validate_kev.py`.)
2. Take `decisions` + `surfaces` from run_poc, call:
   ```python
   from adapter.validate_kev import load_kev, validate
   kev = load_kev("known_exploited_vulnerabilities.json")
   result = validate(decisions, surfaces, kev)
   ```
3. **Expected signal:** `tier_kev_hit_rate` should increase MONOTONICALLY (strategic > tactical >
   skip), `stratejik_lift > 1`. If it increases → the framework works (attention ↔ unseen truth
   are aligned). If it doesn't → either v0/g_A/π is wrong, or in this domain value arises from
   elsewhere (§12 A/C). **Read both outcomes** — a negative is also information.

## Inviolable

- KEV is **NOT a v0 input** (circular). Only output-validation.
- KEV must not have leaked into v0/g_A production (hold-out). If g_A is calibrated to KEV in 03,
  KEV CANNOT be used for validation (a different target is needed) — a hidden loop.
- Honest metric interpretation: lift>1 says "aligned," it does NOT say "the system is perfect."
  Finite, observational.

## Related files
`adapter/validate_kev.py` (skeleton + passive guard + metric), `02_dissal_veri_edinme.md`.
