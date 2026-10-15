# 03 — g_A Weight Calibration (W_CPE vs W_CWE)

> ╔══════════════════════════════════════════════════════════════════════════╗
> ║ **CLOSED (2026-07-15) — this task is NO LONGER VALID.**                  ║
> ║ The "calibrate the W_CPE/W_CWE ratio" plan below was never done. Instead,║
> ║ a more fundamental finding emerged: **g_A was locked to hub popularity** ║
> ║ (Spearman(g_A, weighted-degree)=0.911; confirmed **0.9113** here).       ║
> ║ So the issue is not the weight-RATIO — **the CWE-edge itself is, for this║
> ║ mission, noise not signal** (same bug-class ≠ relation; not colocation). ║
> ║ DECISION: CWE-edges ENTIRELY REMOVED → **g_A = CPE-only** (not a weight  ║
> ║ tweak; not degree-normalization). `positions.py compute_g_A` was updated.║
> ║ Detail + 3 convergences: `adapter/PoC_BULGULAR.md` §"CWE-kenar kararı".  ║
> ║ Calibration phase CLOSED — g_A "coarse but clean," enough for AI arm.    ║
> ╚══════════════════════════════════════════════════════════════════════════╝
>
> The below is HISTORICAL (the plan at the moment the decision was made) — kept for reference, NOT TO BE FOLLOWED.

**Status:** ~~DEFERRED~~ **CLOSED (CWE-edge removed)** · **Blocker:** — · **Effort:** —

## What / Why

`adapter/positions.py`: the g_A graph is built with edge weights `W_CPE=3` (shared vendor:product)
and `W_CWE=1` (shared CWE). Right now these weights are `SEÇİLDİ` (design).

But UNLIKE v0: these are a **testable structural hypothesis** —
"does CPE-adjacency predict *relatedness* (co-exploit / same-chain / same-patch) better than
CWE-adjacency?" This is measurable → genuinely calibratable (unlike v0).

## Why it was deferred

Calibration = a fit to a ground-truth. For g_A, the ground-truth = "genuinely related CVE pairs"
(co-exploit / commit-colocation). **That data is ABSENT in this corpus** (see 02). Calibration
without an external target = fitting to internal consistency (embedding-coherence) = **chasing
one's tail** (Possibility 2, the "v0 vs g_A" section of PoC_BULGULAR). Internal consistency is NOT
ground-truth.

## How to do it (once 02 is complete)

1. Obtain the ground-truth related-pair set (from 02: commit-colocation pairs recommended — clean
   and structural for the kernel). E.g.: `{(cve_a, cve_b): birlikte_düzeldi_mi}`.
2. Weight sweep: build the g_A graph over a `(W_CPE, W_CWE)` grid, compute each surface-pair's
   g_A-proximity, measure correlation with the ground-truth relation.
3. The weight that maximizes correlation = calibrated W_CPE/W_CWE. (W_CPE>W_CWE will probably come
   out, but the RATIO is read from the data — 3:1, 5:1, or 2:1?)
4. Change the status: `SEÇİLDİ` → `ÖLÇÜLDÜ (relatedness'e kalibre, hedef=X)`.
5. **Cascade:** when the weight changes, g_A → G shifts → `params.recompute()`.

## Inviolable — TRAIN/TEST

- Calibration target (e.g. commit-colocation) ≠ system validation target (e.g. KEV). Otherwise
  calibrating and validating against the same thing = a hidden loop.
- Separate a hold-out: calibrate the weights on one portion of the data, verify on another.
- Don't mistake internal consistency for calibration — it is a suggestive signal, not ground-truth.

## Related files
`adapter/positions.py` (W_CPE/W_CWE + PageRank), `02_dissal_veri_edinme.md`.
