# 05 — #Ç3 Early-Warning Test ("does g rise first?")

**Status:** DEFERRED · **Blocker:** multi-year history OR time-stamped embedding · **Effort:** low (code ready)

## What / Why

#Ç3 is the basis for the core's HARD VETO decision (gate_p=2.0): "for surfaces that later turn out
valuable, does their graph-position (g) rise BEFORE the value becomes visible?" If yes → the early
warning comes through the g channel, there is no need to force persistence (π) to the gate → the
hard veto is correct. (v2.1 OPEN MEASUREMENT #Ç3.)

Code ready: `adapter/measure.py::measure_C3` — g_A(t) time-slice + control group + artifact diagnosis.

## Why it was deferred (this round it came out ONE-DIRECTIONAL + UNDERPOWERED)

1. **g_A is nearly static:** over a 46-day window the CWE/CPE adjacencies are time-invariant →
   g_A_early ≈ g_A_late. The control group confirmed this: high-D is 82% "early-positioned" BUT
   skip-surfaces are 88% too → it doesn't discriminate → a positive ARTIFACT.
2. **g_B(t) invisible:** embeddings are time-stampless → half of g cannot be read retrospectively.
3. **One-directional:** only a positive result carries information; a negative proves nothing (it
   may have risen in g_B). This round was neither positive nor negative — unreadable.

## How to unblock it

- **Path A (preferred): multi-year history.** 2-3 years of CVE history instead of 6 weeks → g_A(t)
  genuinely moves (adjacencies form over time). The persistent data pipeline (06) accumulates this.
- **Path B: time-stamped embedding.** Store embeddings with their production date → g_B(t)
  reconstruction becomes possible → the g_B leg of #Ç3 becomes readable too.
- Once both arrive, run `measure_C3`; the control group (skip-rate) should still be the discriminator.

## Inviolable
- Preserve the ONE-DIRECTIONAL interpretation: negative ≠ veto is wrong. Do NOT write "X% positive"
  without a control group (exactly such a false-positive was caught this round).

## Related files
`adapter/measure.py::measure_C3`, `cekirdek/INSA_GUNLUGU.md` (#Ç3 definition), `06_kalici_veri_hatti.md`.
