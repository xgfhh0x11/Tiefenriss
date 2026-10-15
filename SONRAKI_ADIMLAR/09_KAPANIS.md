# 09 — PHASE CLOSURE: Value-Substrate + Connected-Eye + Open-Time-Gate (2026-07-22)

> An honorable closure. This phase **built and calibrated Tiefenriss's value-substrate on real kernel-data**,
> **connected the AI-arm to it**, and **opened the prediction-ledger** (the time-gate has begun). The binding
> constraint is no longer effort but TIME: reality will judge whether the eye sees correctly, months from now.
> That is why we seal it here. We wanted an eye that does not lie; the price of not-lying is waiting. Waiting is standing-at-the-right-boundary.

---

## 1. WHAT WE BUILT (this phase)

**New package `veri/`** — a status-typed, source-agnostic data-layer (English code, a PERMANENT-rule). Real
kernel-CVE-git (8081 CVEs) → 328 subsystem-surfaces. Modules:
- `status.py` — `Status`(MEASURED/DERIVED/OPEN/QUARANTINED) + `Attribute`(value+status+provenance+history) +
  the `measured()` barrier (an OPEN cannot be mistaken for measured) + `evolve()` (the data-state of the time-gate).
- `record.py` `merge.py` `aggregate.py` — two-role source, status-preserving join, subsystem-keyed SurfaceElement.
- `kaynaklar/` (kernel_git/nvd_cwe/syzbot/refs) — real fetchers.
- `pass2_kernel.py` — real-data measurement-report (join-coverage 61%, CWE-distribution, syzbot-zone, refs).
- `wire_core.py` — **the VALUE-MODEL** (below) + `scored_surfaces()` (for the AI-arm).
- `realization_test.py` — g_A external-validity controlled-test.

**AI-arm connection** — `ai_kolu/veri_bridge.py` (substrate→SurfaceContext+tier), `first_look_veri.py` (first 3-surfaces),
`pilot_ccode.py` (20-surface pilot). Ledger: `ongoru_defteri.jsonl` (27 predictions).

---

## 2. VALUE-ARCHITECTURE — decisions and WHY (the intellectual core of this phase)

```
v = v0-density (değer-kapısı)  ·  depth = v0 × π-raw (percentile-kalibre, seçici)
reachability = AYRI-routing-ekseni (değere çarpılmaz)  ·  g_A DÜŞÜRÜLDÜ
```

- **v0 = the coverage-shrunk per-CVE-v0 AVERAGE** (not MAX). *Why:* MAX itself was a size-artifact
  (Spearman(v0,size)=0.705 — bigger-subsystem→more-likely-UAF→mechanically-high). Density solved this (Spearman≈0).
  OPEN-CWEs shrink to the 0.25-anchor (marked, no-fabrication; they `evolve` as coverage↑).
- **g_A was DEMOTED — a three-round convergence, proven with a CONTROLLED-test:** (1) CWE-edge=hub-popularity(0.91) →
  (2) T4 file-co-occurrence=dead → (3) subsystem-overlap=in-sample-dominant BUT externally-HOLLOW. Controlled realization-test:
  under partial control for reachability+v0, partial(g_A,realization|v0)≈0 (robust across 6-configs). g_A's in-sample-dominance
  is a COMMON-CAUSE with reachability, it does NOT CARRY an independent-exploitation-signal. → value is v0-dominant; g_A is confound-decoration.
  It was demoted without touching the core (the adapter gives g_A=1 identity → v=v0).
- **depth = v0 × π-raw, percentile-calibrated.** *Why:* v0-alone saturates on singletons (single-CVE-single-UAF→v0=0.95).
  The core's gate×accumulation mechanism solves this: π=CVE-accumulation → net/ipv4(π=104) at the top, fluke(π=1) at the bottom.
  θ=G_p90 is data-derived (not DECLARED), k is scale-adaptive. Result: **skip 74% / tactical 15% / strategic 10%** (a selective-eye).
- **π is MIXED but legitimately-dominant** (C2 measured it): surface-size(0.58) + reachability-density(0.41, 5.6×). UNLIKE g_A:
  π-size is NOT-FAKE (reachable-code is genuinely-valuable). "Weigh, don't discard" → use π-raw, audit-marked, do-not-normalize.
- **INVARIANT:** π=pressure ≠ reachability=routing. Spearman(depth,reachable)=−0.02 → reachability was not re-inserted into value
  (drivers/net high-π-hardware: depth-top BUT human-arm-routing). π's size(hardware)+density(reachable) components balance out.

**Offensive-actionable output = depth ∩ reachable** (quadrant): fs/smb, mm, net/netfilter, net/sched, net/ipv6, kernel/bpf.

---

## 3. HONEST STATUS (no over-claim)

- **The substrate is solid and honestly-verified.** Every step was measured/controlled, the core was never-touched, regression is complete.
- **The eye is connected and mechanism-generating.** On 23-surfaces, operational+falsifiable hypotheses (fs/smb session-teardown-UAF,
  mm VMA-race, bpf verifier-OOB...), the ceiling-honesty+leak-proofness+provenance discipline held.
- **BUT nothing has realized GOING-FORWARD.** The ledger-predictions are time-gated, unverified. "Plausible" ≠ "correct".
- **The predictions are opus-4.8-as-operator** (not production-Fable-5; API-credit-blocked). Marked → does not contaminate the baseline.
- **The #Ç4-STRUCTURE was built** (held-out 0→3) but **TOO LITTLE for statistical-power** (the chain was verified, a powered-#Ç4 requires hundreds-of-surfaces).

One sentence: *we built the ground the eye sees on, solidly and honestly; the eye was connected to the ground and is
mechanism-predicting; but "does it really see correctly" is in reality's-hands and time-gated.*

---

## 4. THE TIME-GATE — WHAT TO RUN MONTHS-LATER (the closing-half)

The ledger (`ai_kolu/ongoru_defteri.jsonl`, 27 predictions, provenance-marked) is the seed. **~3-6 months later**, for the first-external-evidence:

1. **Refresh the census:** pull new kernel-CVEs with the `/tmp/t4census` logic (after 2026-07). The `veri/kaynaklar/` fetchers.
2. **Re-run the substrate:** `python3 -m veri.wire_core` → new tier-snapshots (for a params-drift-free comparison).
3. **Run realization:** `ai_kolu/realization_detector.py` against the ledger:
   - tier-1 (tier_crossing/tactical-predictions): did the surface-tier cross upward → REALIZED/LAPSE.
   - tier-2 (pending_detector/strategic-predictions): did the named-detector find a matching-CVE (semi-manual: match the new-CVE
     to the prediction-mechanism).
4. **Read #Ç4:** `defter.confirmation_gap()` → highlighted-rate vs held-out-rate (COARSE with 3-held-out; only a sense-of-direction).
   SEPARATE the provenance=opus-as-operator ones (to be read separately once Fable-5 arrives).

**On that day**, the first external-evidence of whether Tiefenriss actually-works arrives: did the eye's mechanism-predictions realize,
and is highlighted above held-out (is there self-fulfilling).

---

## 5. OPEN ENDS (none blocking; when you return)

- **Fable-5 production-operator** (once API-credit arrives) → full-scale (67+ surfaces), separate-provenance, approach a powered-#Ç4.
  (Full-scale must NOT be done now with opus — it would scale the wrong-operator.)
- **Aggregation shrunk-vs-pure** — in v0, coverage-shrinking penalizes arch/x86 (32%-coverage); in pure-mean it rises to #3. Decision-open.
- **XSA-seam-edge** — the guest-host chain (a 2nd source); refs did not provide it in kernel-CVE-git (externally-invalid), the seam-EDGE is in a separate-source.
- **π-λ-recency** — π is currently ~count (gentle-decay); if recency-weighting is desired, a λ-adjustment.
- **Granularity** — subsystem is a 2-level-directory (MAINTAINERS-mapping deferred).

---

## CLOSURE

This phase produced not busywork but **progress**: an honest value-architecture (we demoted the presumed-fancy g_A by proving it),
a connected eye (it is mechanism-predicting), and an open time-gate (reality will judge). The next real-signal
will come from reality — and we now have the discipline to judge it without-anchoring. Breathe. Months-later, run `realization`,
and see the eye's first external-verdict.

*— Record: `adapter/PoC_BULGULAR.md` (full) · `.claude` memory `tiefenriss-adapter-state` (summary) · this-note (closure+resume).*
