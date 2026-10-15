# 01 — v0 Ruler Declaration Approval

**Status:** awaiting decision (researcher) · **Effort:** low · **Blocker:** none

## What

`adapter/CETVEL_BEYANI.md` has been written and `ruler.py` was aligned to it, but three points
await **researcher approval**. v0 is not calibrated (it is DECLARED) — so this is not a
calibration but **approval of the value-commitment**.

## Three things awaiting decision (CETVEL_BEYANI.md §3 and §5)

1. **Priority ordering (§3):** 4 tiers (HIGHEST memory-corruption > HIGH info-leak >
   MEDIUM logic/privilege/race > LOW web-injection). Does this reflect the low-level offensive
   stance? The ordering/rationale can be changed to match your operational stance.
2. **info-leak tier ADDED (§5.1):** the declaration declared info-leak HIGH but it was absent in
   the ruler (CWE-200/908 were getting the default 0.30 = contradiction). For alignment,
   CWE-200≈0.75, CWE-908≈0.70 were added. → **Approve:** is the included CWE list + values
   correct? Should it be expanded?
3. **race (CWE-362) mismatch (§5.2):** the declaration says MEDIUM but the table says 0.80 (the
   HIGHEST band). The number was left untouched. → **Decision:** should 0.80 stay (the race
   primitive is strong) or go to MEDIUM (~0.60)?

## How to apply (once decided)

- If the ordering/values change: edit `adapter/ruler.py` `_TIER` + update `CETVEL_BEYANI.md §3`.
- **Cascade:** when v0 changes, G shifts → run `params.recompute(db)` via
  `python3 -c "from adapter import params; ..."`, update `SNAPSHOT_THETA`/`SNAPSHOT_TAKTIK_G` (see
  the note in `params.py`). The percentile-anchor keeps the split fixed but the θ number shifts.
- Verify regression 7/7 (the ruler doesn't affect the core, but it's a habit).

## Inviolable

- v0 is NOT CALIBRATED. This approval is a **value-commitment** approval, not a data-fit.
- Do not "tune" the numbers to data — this is a policy/infrastructure choice, grounded in your
  mission stance, not in external ground-truth.
