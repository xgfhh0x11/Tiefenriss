# Tiefenriss Adapter PoC — Findings & Decision Notes

> For the reviewer. The CORE WAS NOT TOUCHED (regression 7/7 passes). The Prozessfall DB was used
> READ-ONLY (nothing was written). All results are over CPE-CLEAN surfaces
> (no keyword-guessing — nothing mixed in).

## What was built
The `adapter/` package, one-directional dependency (adapter → core, never the reverse):
- `core_bridge.py` — the single point that binds the core (plain import; the core is `Tiefenriss/cekirdek/`)
- `ruler.py` — the v0 static CWE-family ruler (**CHOSEN**)
- `surfaces.py` — DB → CPE-clean surfaces `(primary_cwe, vendor:product)`
- `positions.py` — g_A (weighted PageRank, **weights CHOSEN**) + g_B (embedding ≥0.80)
- `embeddings.py` — embedding for g_B (missing ones produced in memory, not written to the DB)
- `build.py` — Surface → `ElementProfile` (the heart of the adapter)
- `measure.py` — the three measurements
- `run_poc.py` — end-to-end (`python3 -m adapter.run_poc`)

## Signal mapping and epistemic status
| Core | Source | Status |
|---|---|---|
| v0 | CWE family-tier | **CHOSEN** (static; CVSS not used; compound→max) |
| g_A | ~~shared CPE (W=3) + CWE (W=1)~~ → **CPE-only** PageRank | **MEASURED** (Type A) — the CWE-edge was REMOVED, see §"CWE-edge decision" |
| g_B | member-embedding average, cosine ≥0.80 → PageRank | **DERIVED** (Type B) |
| signals | member CVE publication days → Signal(t=day) | **MEASURED** |
| spread_count | distinct vendor:product in which primary_cwe is seen | **MEASURED** (coarse, see S4) |

## Measurement results (141 surfaces, ≥2 distinct-day impacts; now=42d)
Tier distribution: **tactical 58 / strategic 39 / skip 44** (discriminating — not saturated).

- **#Ç1 (A/C → A-share):** **73%** of value comes from the measured neighborhood (g_A), 27% from the derived
  one (g_B). Value is predominantly **MEASURED** → epistemically-clean. (§12: in the direction of "if it's A,
  the system works".)
  > ⚠️ **RETROACTIVE CORRECTION (see §"CWE-edge decision"):** this "epistemically-clean" reading was measuring
  > the g_A of that time, which was **hub-popularity** (Spearman(g_A, degree)=0.911). MEASURED ≠
  > MEASURED-THE-RIGHT-THING. After the CWE-edge was removed, #Ç1 was **re-read** with CPE-only → see the
  > §CWE-edge decision below.
- **#Ç2 (g_B/g_A):** **GLOBAL (true weight)** — g_B was computed over the entire 2947 CPE-clean surface
  universe (15154 sim≥0.80 edges, the SAME universe as g_A → apples-to-apples). Ratio mean **0.796** / median
  0.811 (g_A 0.525, g_B 0.393). The difference from the earlier subset-relative upper-bound (0.84) is **~5%**
  → as a proxy-material it was not inflated. Reading: the raw derived signal is ~80% of the measured one; but
  the policy w=0.5 reduces it to **~26% in value** (consistent with the #Ç1 A-share of 0.738). The w
  calibration basis: if the derived one is trusted less, w is lowered; at w=0.5 B's value-share is ~26% (a
  defensible balance). The embedding was written to the npz cache (NOT to the DB — read-only preserved);
  re-run 1.4s.
- **#Ç3 (does g rise first?):** **COULD NOT BE READ — DEFERRED.** The raw result APPEARED 84% positive, but
  **the control group collapsed it:** on skip-surfaces it was also 84% → early-positioning does not
  discriminate high-D. Reason: g_A is almost static in this corpus (mean shift 0.063; CWE/CPE neighborhoods
  are time-invariant + an early bulk-dump). Also g_B(t) is invisible. **Decision: the #Ç3 verdict is
  deferred**; until multi-year history or time-stamped embeddings arrive, it cannot be tested with this data.
  (One-directionality preserved: the negative was never proof anyway; the "positive" here also came out an
  artifact.)

## Deviations / decision-points (to the reviewer)
1. **Package name — RESOLVED (2026-07-05):** the core was moved to the `Tiefenriss/cekirdek/` sub-directory
   (content-preserving, hash byte-for-byte identical). The layers are now sibling packages: `cekirdek/`
   (sealed) · `adapter/` · `prozessfall/`. The shim was REMOVED entirely, `core_bridge` is a plain import.
   Running: from the project root `python3 -m cekirdek.test_kadran` and `python3 -m adapter.run_poc`.
   Regression 7/7 verified native (shim-less) from the new location.
2. **Selection artifact (caught & fixed):** the first attempt selected "the richest surface" → all saturated
   strategic (π~60). The richness-cap was REMOVED; the population = the "≥2 distinct-day impacts" quality
   gate. Lesson: the PoC population must not be selected by richness.
3. **π scale / saturation:** median π~1.25 (compatible with the synthetic quadrant regime → θ=0.30
   reasonable), but a dense tail (chrome CWE-416, 106 impacts) saturates at π~50 and bunches at D=1.0. This is
   NOT A BUG — the formalization's **Finding 3** (in the upper region saturation erases discrimination, a
   feature). Still, the top ~15 surfaces do not separate from one another; the operator makes the distinction
   (EOS step 4).
4. **ρ definition — RESOLVED (`surface.places`).** The old ρ = cwe-footprint (CWE-level → the same for all
   fragments → double-count; all 14 fragments of CWE-416 inherited ρ=0.82 and became artificially strategic).
   **The new ρ = the distinct vendor:product that the surface's MEMBERS touch** (surface-specific). Result: a
   narrow surface (single place, e.g. kernel) → ρ=0.25 fixed-low → the π ranking persists (usb/mm/drm on top,
   single-impact acpi/can at the bottom); a surface truly spread across many products → ρ high. The ρ range is
   now 0.25–0.94 (previously saturated at ~0.95). Compatible with v2.1: a narrow surface = a deep/narrow type
   (high π, ρ≈0). **Cascade:** when ρ changed, G dropped → calibration was recomputed (θ 0.226→0.165) BUT
   thanks to the percentile-anchor the full-pop split stayed FIXED (74/14/10) — with a frozen θ it would have
   broken. This validated the percentile-anchor decision.
5. **v > 1.0 is possible:** when g_A + w·g_B > 1 (e.g. 0.65 + 0.5·0.92), v0·g > 1. The formalization allows it
   (v0·g, g≤1.5). If [0,1] is wanted for reporting convenience, g is clamped/normalized. Minor.
6. **CHOSEN parameters (not a measurement, noted in the code):** the v0 family-tier table; W_CPE=3/W_CWE=1;
   the temporal edge skipped in this corpus (46d firehose → does not discriminate); #Ç3 TAU=0.8.

## θ/k CALIBRATION (a separate round — `adapter/calibrate.py`)
POPULATION: ALL 2947 CPE-clean surfaces (not 141 — the noise floor included). G is computed once (independent
of θ/k), θ/k are scanned analytically, the core's own opening()/_classify_tier() are used (core.py IS NOT
TOUCHED).

**FINDING — an early worry was INVERTED:** the real full-universe G distribution is extremely right-skewed:
p50=**0.030**, p75=0.089, p90=0.226, p99=1.046, max=16.0. The current **θ=0.30 ~corresponds to G_p92** → on
the full population it is **already selective: 74% skip / 20% tactical / 7% strategic** (2174/578/195). So the
early "too strategic" impression was a **141-subset (signal-filtered) artifact**; on the full population θ=0.30
is well-placed. Calibrating with the honest population prevented accidentally LOWERING θ relative to the
biased-subset (had I looked at the subset I would have mis-calibrated θ).

**Two secondary findings:**
1. **θ is hyper-sensitive:** because the G median is piled up at 0.03, the tier boundaries are very sensitive
   for θ∈[0.2,0.4] — a small θ change moves thousands of surfaces. θ must be chosen not as a number but as a
   STANCE, and the G-percentile it corresponds to must be RECORDED (reproducible as the data grows).
2. **k does not change the open/close COUNT** (D≥0.5 exactly at G=θ, independent of k); k only tunes the
   transition sharpness (k=4 soft → k=16 a sharp skip boundary).

**DECISION (2026-07-05, approved) — `adapter/params.py`:** θ and the tier thresholds were taken out of the
synthetic constants and anchored to the PERCENTILES of the G distribution (the stance stays fixed even as the
data grows). Stance: **strategic = G≥G_p90 (θ here) · tactical = G_p75..G_p90 · skip = G<G_p75 · k=8.**
Snapshot (2947 surfaces, after the ρ-fix): θ=0.165, tier D-thresholds 0.30/0.50.

| full-pop (2947) | skip | tactical | strategic |
|---|---|---|---|
| old (θ=0.30, tier 0.15/0.55 synthetic) | 2174 | 578 | 195 (6.6%) |
| **new (data-anchored)** | **2209 (74%)** | 442 (14%) | **296 (10%)** |

"Look deeply at the top-10%" was realized; 74% skip (attention-economy); all boundaries are data-anchored (the
half-calibrated inconsistency was removed). `params.recompute(db)` refreshes the thresholds as the data grows,
the stance (p90/p75) stays fixed. k=8 fixed (not critical; the D≥0.5 count is independent of k). Rationale
(G_p90 instead of θ=0.30): θ=0.30 is a frozen synthetic constant, today ~p92; as the data shifts, selectivity
would change unnoticed — the percentile-anchor prevents this (epistemically-clean).

## Keyword-subsystem comparison (`adapter/compare_subsystem.py`)
CPE-clean (MEASURED) vs keyword-derived (DERIVED) subsystems SIDE BY SIDE — SEPARATE g_A graphs, not mixed.
Over the kernel CVEs (1329).

**Keyword reliability breakdown:** clean(single-match)=556 (41%, SIGNAL) · ambiguous(multi)=148 (11%,
excluded) · zero=625 (47%, unrecoverable) → **<41% coverage**.

**SIGNAL (real, narrow):** CPE lumps all kernel CVEs into a SINGLE `linux:linux_kernel` surface per cwe (25
surfaces); keyword opens this into 107 fine surfaces — localizing CWE-416 to xfs/usb/mm/drm/netfilter/ksmbd.
**Valuable for attention-DIRECTION** ("which subsystem to look at").

**ROTTEN ('too good' filtered out):** the keyword tier distribution APPEARED strategic 50/107, but this is a
**ρ double-count artifact** — even though the 14 fragments of CWE-416 have π=0.14-0.90 (low), they ALL inherited
ρ=0.82 (the same footprint) and became artificially strategic. **The split D-scores are UNTRUSTWORTHY.**
Keyword is a DIRECTION-HINT layer, NOT a source of scored-surfaces.

**DECISION:** keyword is kept as a separate, low-confidence, DERIVED direction-hint layer; it is NOT MERGED
with CPE's MEASURED g_A. Its value is not in scoring but in attention-steering.

### Direction-hint integration (`adapter/hints.py`) — DONE
Keyword was bound as an ANNOTATION layer: next to the scored CPE surface (MEASURED, D/tier/g_A UNCHANGED) a hint
is added for "which sub-subsystem is active inside it" — a separate `{sid: hint}` dictionary, it touches the
core/ElementProfile NOT AT ALL. Example (run_poc output):
```
[stratejik D=1.00] CWE-416×linux:linux_kernel
    → mm(5) drm(4) usb(4) bluetooth(3) ksmbd(2) xfs(2) +8  [kapsam 28/68, belirsiz 14]
```
Principles: (a) only a CLEAN single-match counts; (b) coverage/ambiguity is shown TRANSPARENTLY; (c)
kernel-keyword is applied ONLY to kernel-product surfaces (`KERNEL_VPS`) — a cross-domain mis-match is
prevented (chrome "drm"=DRM≠kernel DRM was filtered out); (d) a non-kernel surface = an empty hint (honest).
Coverage 17/141 scored surfaces (richest in the kernel that CPE lumps). The score stays MEASURED, the hint is
marked DERIVED+low-confidence.

## Completed rounds
- ✅ θ/k + tier data-anchored calibration (`params.py`, percentile stance G_p90/G_p75)
- ✅ g_B global (#Ç2 true weight 0.796)
- ✅ keyword-subsystem comparison (separate, signal vs noise measured)
- ✅ ρ definition fixed (`surface.places`, double-count resolved, cascade re-calibrated)
- ✅ keyword direction-hint layer integrated (`hints.py`, does not enter the score, separate+marked)
- ✅ v0 ruler declaration (`CETVEL_BEYANI.md`) — DECLARED, not calibrated; the infrastructure-ruler status was fixed
- ✅ KEV-as-validation hook skeleton (`validate_kev.py`, active once the data arrives; NOT a v0-input)

## v0 vs g_A — resolving the calibration trap (2026-07-05)
A critical distinction: "calibrate v0 and g_A" is two DIFFERENT things, and one of them CANNOT be calibrated.
- **v0 = the epistemic-infrastructure RULER** (spec §7-8), fixed like λ, NOT policy like θ. IT IS NOT
  CALIBRATED → it is DECLARED (`CETVEL_BEYANI.md`). Tuning its value to an external ground-truth is (a)
  circular — it buries the answer the system is supposed to discover; (b) a category-error — it turns the
  ruler into a measurement. KEV/exploit data DOES NOT ENTER v0; it goes to the validation of the
  system-OUTPUT.
- **g_A weights (W_CPE=3/W_CWE=1) = epistemic-but-CURRENTLY-BLOCKED.** A testable structural hypothesis: "does
  CPE-neighborhood predict relatedness (co-exploit) better than CWE-neighborhood?" BUT the external TARGET
  DATA needed for calibration is NOT in this corpus: **KEV · exploit-chain data · commit-colocation (CVEs
  fixed in the same commit).** Until this data arrives it **stays CHOSEN** — internal-consistency
  (embedding-coherence) is NOT ground-truth, and calibrating to it is chasing-one's-tail. **Train/test
  hygiene:** once the data arrives, if the weights are calibrated to a target they must be validated on a
  SEPARATE hold-out (calibration target ≠ validation target; otherwise a hidden loop). → g_A calibration was
  DEFERRED, the target data was named.

## CWE-edge decision — g_A = CPE-only (2026-07-15) · FOUNDATIONAL-CLEANUP, the CLOSURE of the calibration-phase

> This INVALIDATES the "g_A weights CHOSEN/deferred" stance (the v0-vs-g_A section above). The issue is no
> longer "calibrate the W_CPE/W_CWE ratio" — **the CWE-edge itself is not signal but pollution for this
> mission.** No weight-tuning was done; the edge was removed ENTIRELY.

### Finding — g_A is locked to hub-popularity
- **Spearman(g_A, weighted-degree) = 0.911** → ~83% (0.911²) of g_A's variance is pure degree
  (=hub-popularity). CONFIRMED on this machine (2026-07-15): 0.9113 (weighted degree; unweighted
  distinct-neighbor 0.823). A 2947-surface universe, 77660 edges. Value was measuring not "relational
  position" but "how many cliques one belongs to".
- Mega-CWEs collapse when degree-corrected (CWE-787's share 81%→3%, etc.); in the top 50 g_A, the mega-CWE
  share is **34%→0%**. High g_A = an artifact of large CWE-clique membership (giant bug-classes like
  CWE-79/787/125 connect everyone to everyone → artificially high PageRank).

### Three independent convergences (to the same conclusion)
1. **Domain-intuition:** cross-product CWE-proximity (the same bug-class in different products) is noise for
   this low-level-offensive mission — "both are UAF" does not make two surfaces related.
2. **Colocation:** same-CWE code-colocation IS NOT PREDICTED (the same bug-class in different repos; they are
   not fixed together). The "relation" the CWE-edge implies is not in the data.
3. **This test:** CWE-cliques are pure hub-popularity (Spearman 0.911) — structural confirmation.

### DECISION — REMOVE the CWE-edges, g_A = CPE-only
- **NOT degree-normalize.** That tries to rescue the dirty-signal + spawns its own artifact (near-singleton
  inflation: low-neighbor nodes rise artificially). The clean solution: drop the dirty edge.
- g_A's status stays **MEASURED** (the edges are still from the data; now CPE-only, hub-popularity-free).
- **APPLIED (2026-07-15):** `positions.py compute_g_A` → only W_CPE edges. Regression 7/7 preserved.

### #Ç1 retroactive — re-reading with CPE-only
The old #Ç1 said "74% of value from g_A → epistemically-clean"; but that g_A was hub-popularity → the
**"epistemically-clean" reading WAS WRONG** (measured ≠ measured-the-right-thing). It was HONESTLY re-read with
CPE-only g_A:

**#Ç1 CPE-only result (2026-07-15, a single reading — NOT a calibration-round):**
- **A-share 0.814 (all) / 0.834 (non-skipped)** — HIGHER than the old hub-popularity 0.738.
- g_A mean 0.525→**0.916**, g_B/g_A 0.796→**0.545** (the g_A denominator grew → the derived-share dropped).
- **Honest reading:** value is now **measured AND measures-the-right-thing.** The old A-share was inflated by
  CWE-clique hub-popularity (measured-but-wrong-thing); the new A-share is from **CPE-neighborhood** — the
  same vendor:product = genuinely related (a defensible relatedness), NOT bug-class popularity. → g_A's
  epistemically-clean status is now REAL (the MEASURED label was honestly earned).
- **COARSENESS WARNING (consciously accepted, NOT FIXED):** CPE-only enlarges the kernel-lump — CPE lumps the
  entire kernel into a single `linux:linux_kernel` vp-clique → the g_A of kernel surfaces saturates at 1.0,
  the subset tier looks strategic-weighted ({skip 14, tactical 42, strategic 85}). This **kernel-lump (4B)** is
  a coarseness SEPARATE from the CWE-fix; subsystem-granularity would resolve it but that is
  endless-calibration → LEFT. g_A is "coarse but CLEAN": the hub-popularity pollution is gone, the resolution
  stayed coarse. A sufficient ground for the AI arm (the AI refines attention-direction with the hint layer +
  its own hypothesis anyway).

### The calibration-phase CLOSED (a conscious boundary)
The fix = foundational-cleanup (MANDATORY: the AI arm will be built on top of g_A, g_A must measure the
right-thing). **kernel-lump / subsystem-resolution / W-fine-tuning WILL NOT BE DONE** — these are "making the
coarse-but-clean better" = endless-calibration. g_A is now **coarse but clean** → a sufficient ground for the
AI arm. The next phase: AI-ARM ARCHITECTURE (not code, design first).

## VISION — what Tiefenriss is BUILDING (2026-07-17, context-ground)

> This is not a task but a GROUND. Every architectural-decision below (core, ledger, detector, exposure)
> serves it. The lens of every design-point from here on: "does this make the eye MORE-CORRECT (calibrated),
> or powerful-but-DISTORTED (echo risk)?"

### An eye, not a tool
Tiefenriss is not a security-TOOL — it is the **mechanical form of the researcher's operational eye**; the
externalization of a cognitive-architecture woven over years. Not a copy/representation (a portrait), but a
**LIMB (a prosthetic eye)**: one that looks the WAY the researcher looks, but at a SCALE he cannot — across
millions of surfaces, tirelessly, with the same multi-layered manner of seeing.

**Why rigor = not ornament, but the eye's CORRECTNESS:** if it were a tool, "good enough" would suffice. But
this is an EYE. A dirty eye makes you see wrong; an eye that falls into an echo chamber shows its
own-illusion; an undisciplined eye cannot tell what-it-saw from what-it-made-up → **IT LIES TO YOU.** A
powerful-but-distorted eye is all the more dangerous the more powerful it is. All our rigor (g_A
hub-cleaning, held-out, the time-gate, status-labeling) = **calibrating our own eye.** Power and discipline
scale together.

### How the eye works (the layer-stack)
scope → surface mapping (the adapter) → the **core mathematical decision mechanism** pulls elements
(attention-allocation = AT THE SAME TIME energy/performance allocation: the AI gives its full-power to a
strategic surface, does not touch a skip-surface — **the core = the AI's energy-governor**) → the AI models a
surface strategically+operationally, produces/discovers potential attack-paths and stress-points → the output
is **100% OPERATIONAL** (surface, path, stress-point).

### Multi-lens discovery (MOST CRITICAL — the most misunderstandable)
The AI looks at a surface not through a SINGLE lens (technical) but through MANY lenses: philosophical,
sociological, historical, psychological, epistemic. **BUT these angles are not OUTPUT, but a POINT-OF-VIEW.**
- **WRONG:** PRODUCING a human-interpretation like "this CVE reflects such-and-such sociological-pattern" →
  unfalsifiable, collapses discipline.
- **RIGHT:** the human-angles are a **DISCOVERY LENS.** A different manner of thinking = makes a different
  stress-point visible. Historical: "this bug-type historically clusters under such-and-such condition → is a
  similar condition present here?" Psychological: "what does the defender ignore, what does the attacker try
  first?" Epistemic: "what here is BELIEVED to be known but is an ASSUMPTION → the place the assumption breaks
  is the stress-point." The output is still 100% operational; the lens only said WHERE to look.

**Why it is powerful:** a rival with a single-lens (technical) finds the KNOWN stress-points. Multi-lens finds
the UNSEEN ones — because the unseen lives in the BLIND-SPOT of the single lens. A different lens = a different
blind-spot; the UNION of the lenses sees what none of them alone can. "An unseen stress-point" =
**multi-blind-spot-closure.**

### How the vision is RECONCILED with epistemic-discipline (critical)
The vision is NOT unbounded — it REQUIRES the strictest discipline. Because multi-lens (especially
philosophy/sociology) is the layer most prone to being unfalsifiable. The reconciliation:
- Lenses GENERATE hypotheses (discovery), measurement CONFIRMS. A lens may be unfalsifiable but the
  stress-point the lens FINDS is measurable (either a real vulnerability exists or it does not).
- Every stress-point produced **starts type-2 → gets status-labeled → passes through the time-gate → is
  tested against reality → if it materializes, type-1.** Philosophy DISCOVERS, the core+reality JUDGE. The
  human-layer presses the GAS, the epistemic-core holds the STEERING WHEEL. → Tiefenriss carries BOTH the
  multi-layered-view AND stays epistemically-honest.

### The researcher in the loop (not a prosthesis, but co-seeing)
Tiefenriss takes the MECHANICS of the gaze (how it looks), NOT its SOURCE (intuition, lived experience —
uncodeable). That is why the researcher is IN THE LOOP: it is HE who evaluates the predictions, directs the
lenses, interprets reality. Tiefenriss is the eye's-RANGE, but the one LOOKING is still the researcher. One
seeing-system: machine scale+repetition, human intuition+interpretation. (A one-to-one match with the A-mode /
human-auditor / evolutionary-path we built — **the vision confirms the architecture.**)

## MULTI-SCALE VIEW — two-kinds-of-consistency + blind-spot discipline + perspective-axes (2026-07-18)

> The operational sharpening of §VISION. The VISION said "rigor = eye-correctness"; this section separates
> WHICH rigor is eye-correctness (cannot be sacrificed) from WHICH is view-richness (can stay coarse).
> Tiefenriss is NOT a measurement-theorem/formal-proof/showcase — an operational+strategic EYE (Sherlock-view
> + Reddington-positioning). Measurement is not Tiefenriss's PURPOSE but its DISCIPLINE. The purpose: to see
> with multi-lens what the human-eye cannot, to position strategically, to predict attack-paths + their
> evolution.

### META-PRINCIPLE — Two kinds of consistency (CONFLATING = a fundamental error)
- **TYPE-A (the FOUNDATION of operationality):** core-mathematics · held-out leak-tightness ·
  realization-measurement. If it loosens THE EYE LIES. NEVER sacrificed, not left-coarse, not coordinated →
  protected/solved.
- **TYPE-B (which may stay coarse for operational-value):** perspective-view · multi-lens richness. Trying to
  make it perfectly-consistent smothers the real work. It may stay coarse, it is COORDINATED.
- **DISTINGUISHING TEST:** if a consistency loosens, does the eye LIE (A → protect/solve) or does the view
  merely COARSEN (B → coordinate)? Without making this distinction one cannot say "consistency is good/bad".
  The generalization of the `coarse-but-clean` decision: the kernel-lump is Type-B coarseness (leave it) — but
  the realization-blindness it GIVES RISE TO is Type-A (solve it).

### BLIND-SPOT DISCIPLINE
The system does not try to SOLVE blind-spots (a Gödel-like infinite-regress, cannot-be-audited-from-inside —
the İ6 echo-chamber logic) → it COORDINATES them and LEAVES them: "there is uncertainty here, don't go after
it but KNOW it." **BUT coordinate-and-leave is ONLY for TYPE-B.** A Type-A blind-spot (a measurement-base) is
not coordinated — it is solved/protected. To coordinate a Type-A blind-spot = to dress up the eye's lie as
"handled" → WORSE than an uncoordinated-blind-spot (because it is hidden).
> The trap: opening the kernel-lump for the sake of measurement = mistaking Type-B coarseness for Type-A and
> straying from the real-work. DO NOT OPEN IT. The right solution is AU-1: move the measurement to the right
> axis without opening the lump.

### AU-1 — STRATEGIC-EYE (A) + VIEW-FILTERS (B) — CLOSED (2026-07-18)
Multi-lens is present AT THE INPUT (discovery: philosophical/psychological/historical/… = "where to look", the
expansion of İ1's multi-reading audience). AT THE OUTPUT the structure closed to the **strategic-eye +
view-filters** pair — the perspectives are NOT "separate value-axes" (that multi-axis-realization-vector
interpretation was replaced by the tile-boundary, below):

- **STRATEGIC-EYE (TYPE-A, the measurement-base):** produces a single RICH, all-dimension, multi-lens
  evaluation. **Value is computed HERE** — including the measured dimensions (exploit-dev → primitive/v0,
  red-teamer → chain-value). Signal-bearing, sound, NEVER left-coarse. **All the measurement-load is here.**
- **VIEW-FILTERS / TILES (TYPE-B, the presentation-layer):** look at the same rich-evaluation from a different
  reading-angle and RE-RANK/EMPHASIZE it. Not a value-engine, a reading-lens. exploit-developer + red-teamer =
  strongly measurement-bound (anchored to an existing-number); performance-engineer + researcher = a flexible
  presentation-tile (a concrete-number is not required).

**TILE-BOUNDARY (what keeps the tiles clean; the final-form of the CRITICAL CONDITION):** a tile EMPHASIZES
but does NOT INVENT NEW-VALUE.
- **Legitimate:** bring-to-front/re-rank the dimensions the strategic-eye ALREADY-saw for that perspective.
- **Forbidden:** adding a new-value the strategic-eye DID NOT see → the tile secretly turns into a
  VALUE-ENGINE = a Type-A leak (speculation, echo-chamber). A tile = the RE-FRAMING of existing-richness, NOT
  the PRODUCTION of new-richness.
Thus a tile DOES NOT REQUIRE measurement (presentation) BUT also DOES NOT PRODUCE speculation (no-new-value). A
single rule gives two guarantees.

**CONSEQUENCES:**
- **Tiles do NOT NARROW the eye's richness:** the eye always produces a full-evaluation; whether or not a tile
  is selected, the eye does not see-less (a tile = a read-only emphasis-projection ON the full-output; NOT a
  filter that selects-a-subset-and-DISCARDS the rest).
- **CEILING-SATURATION (structurally) is solved:** the motivation = subset 60% strategic / kernel 13-17 (live
  2026-07-18) → a single-scalar core-tier saturates at the ceiling, layer-1 cannot confirm + #Ç4 goes blind.
  When value is read in multiple-dimensions, a ceiling in one dimension ≠ a ceiling in another; because the
  tiles do not narrow richness, the reading stays full. *(The realization-MOVEMENT signals — exploit-dev =
  weaponization/KEV, red-team = colocation — await T4-external-data: structure-now, measure-later. See
  §CWE-edge/T4.)*
- **#Ç4-hygiene is preserved:** only the measurement-bound dimensions (in the strategic-eye) participate in
  realization; because the tiles carry no confirmation-claim they DO NOT FORCE #Ç4 / cannot be a
  measurement-echo-chamber (this is how the multi-axis-realization's per-axis held-out-N split worry is
  resolved).
- **Two-kinds-of-consistency:** measurement (A) is sound in the strategic-eye; presentation (B) is flexible in
  the tile.

**STILL OPEN (outside AU-1, recorded — DOES NOT block):** which existing-dimension the researcher/perf-eng
tiles will emphasize (g_B / novelty etc.) → a Pass-2/fill detail. The perspective STRUCTURE (tile-mechanics) =
design; the CONTENT (what is emphasized for this surface in this perspective) = LLM-Pass2.

### AU-2 — THE PHENOTYPIC-VIOLATION LINEAGE (attack-path evolution) — SCOPE CLARIFIED (2026-07-18)
Attack-paths/vulnerability-classes are NOT static — they have an EVOLUTION: backward "where-did-it-descend-from"
(lineage) + forward "where-will-it-go" (mutation-prediction). "Phenotypic-violation" = the mutation/descent
pattern of a vulnerability-class; the system must SEE it (backward) + PREDICT it (forward).

**SCOPE DECISION (before Pass-2, to prevent double-setting-up the operator):** two halves, two separate
statuses/homes:
- **BACKWARD = lineage = SEEING → MEASURED** (researcher decision 2026-07-18). Past-descent is a measurable
  relation (time-ordering + technical-similarity g_B + common-root colocation), of the MEASURED/DERIVED family.
  Home: a **deterministic A3-detector** (an annotation ON the atoms), NOT operator-asserted (having the
  operator produce the measured thing pierces the İ-discipline: the operator is only for speculative-forward).
  → it DOES NOT TOUCH the operator-interface.
- **FORWARD = mutation-prediction = PREDICTING → OPERATOR, but fits the EXISTING schema.** stress_point +
  layer-2 (FUTURE_DETECTOR, a named phenotypic-violation-detector + bounded-horizon). NO new PredType/gate —
  the layer-2 rails were designed exactly for this ("I can name the falsification but cannot measure it today").

**OPERATOR STANCE: lineage-BLIND, evolution-SHAPED.** The Pass-2 operator does not need the backward-lineage
feed; with its own multi-lens (historical/epistemic lens) it produces a forward-evolution prediction.
Philosophy DISCOVERS (forward-mutation), reality/detector JUDGES (did the mutation happen). No order-dependency
→ **the operator is set up ONCE.**

**RESULT: AU-2 has NO part that touches the operator-interface → the Pass-2 double-setup risk is GONE.** Two
record-locks (no-code):
- **Lock-1 (confirmation):** forward-evolution = the existing atom-types (stress_point/transition) + layer-2 →
  the operator output-type-enum FREEZES.
- **Lock-2 (reserve-decision):** `lineage_ref` = a default-None field, to be added with a genealogy-detector
  in A3 (non-breaking PROVEN: the A2-field-expansion did not break test_a1 7/7). NOT added NOW
  (dead-schema/anti-speculation); the reserve = a DECISION + a name.

**DEFERRED TO A3 (does not affect the operator):** the genealogy-detector (backward-construction) · the
phenotypic-violation realization-detector (did the predicted mutation appear) · T4-data (colocation) · an
optional `Direction.EVRIM` (for a per-direction horizon, a default-compatible enum-add).

### This round: the NET-BUG fixed + recorded deferrals to A3
- ✅ **NET-BUG (Type-A) FIXED (2026-07-18):** `yayim.py` `tier_at_creation or "atla"` silent-default (if there
  is no snapshot, a trivial-realization; a violation of the İ9b "garbage-not-silently-fixed") → if there is no
  snapshot, **REJECT** (reject-log, quarantine). A `stub_operator` R9 adversarial-case was added (it passes the
  boundary, gets rejected at the tier-check). regression 7/7 · test_a1 7/7 · test_a2 8/8 preserved; the
  production ledger is EMPTY.
- **DEFERRED TO A3 (recorded, no-code):** params-drift (a θ-shift can leak into the epistemic-verdict; the
  `tier_at_creation` label is in the creation-params, the comparison is in the current-params → the code does
  not give the "SAME params" claim the comment makes; latent in the static-corpus) · horizon 180d vs corpus
  46d (needs live/multi-year data; Pass-2 tests only pending-plumbing, not the prediction-ACCURACY) ·
  loop-safety İ6 perturbation + İ8 autonomy.

### A2 PASS-2 BUILD — a real operator + reality-gate + LABEL-HONESTY (2026-07-18)
A REAL Claude operator was plugged into Pass-1's operator-agnostic pipe. `ai_kolu/llm_operator.py`: an
HONESTY-CONTRACTED prompt + `AnthropicBackend` (LIVE, `claude-fable-5` + refusal-fallback opus-4-8) +
`RecordedBackend` (reproducible) + a parser (free-JSON → a typed Candidate). The operator-cognition = Fable-5
(this session) over REAL surfaces (CWE-125×linux ceiling-37CVE, CWE-77×wavlink tactical-9CVE), saved to a
fixture. `test_pass2` **6/6**, core/A1/A2 preserved, the ledger EMPTY.

**Three evaluations (the researcher's question):**
- **Q1 does the pipe carry cleanly → YES.** Operator free-JSON → parser → Candidate → emit→boundary→fill→
  assembly; the type-flow is clean, no crash. The energy-governor (tier→lens-count) was preserved.
- **Q2 label-honesty (especially the CEILING) → structuralized.** The honest operator DID NOT PRODUCE a layer-1
  at the ceiling-surface (strategic) (both predictions were layer-2, because the tier cannot be
  upward-crossed) and self-rejected its philosophy-lens as `signal_kind=none` (the boundary threw it out at
  layer-3). A **CEILING-GUARD was added** (`boundary.py`, AU-1 operational): at the ceiling `tier_crossing` is
  unfalsifiable (cannot-cross-upward-positively) → rejected AT THE BOUNDARY, forced to layer-2. Against an
  operator-lie, a structural backstop (subset 60% strategic → critical). Regression preserved (stub
  tier="atla", not the ceiling).
- **Q3 does the reality-gate catch speculation → STRUCTURALLY YES, SEMANTICALLY NO (an honest limit).** The
  boundary catches the STRUCTURALLY-fake (empty-field · none/philosophy · a CWE outside-the-closed-set ·
  ceiling-mislabel). BUT it DOES NOT CATCH the SEMANTIC-lie: an empty-philosophical-intuition + a generic
  `falsification="tier rises"` + a `tier_crossing` (non-ceiling) PASSES the boundary (structurally-valid).
  **The boundary is necessary-but-NOT-SUFFICIENT:** semantic-label-honesty is judged only by REALITY
  (#Ç4/realization: a lie-layer-1 LAPSES over time, the per-lens hit/lapse profile degrades). This is the
  REASON held-out + #Ç4 are set up on day-1. **The honest constraint:** on the current static-corpus #Ç4
  cannot run (awaiting T4-data + realization) → Pass-2 PROVES the PLUMBING+STRUCTURAL-honesty, not the full
  SEMANTIC-loop (that is post-T4).

## AI ARM ARCHITECTURE — PRINCIPLES (2026-07-16, researcher+reviewer+CC triple consensus)

> This section is a record of DECISIONS/PRINCIPLES — the AI arm is NOT YET BEING BUILT. This is the epistemic
> foundation that must be laid before the build begins. The code side is only `ai_kolu/ongoru_defteri.py` (an
> empty schema). The core was not touched, regression 7/7. These principles are sealed-intent; the build
> conforms to them.

### İ1 — Three capabilities, two readings
Discovery · sense-making · potential-attack-path generation. The audience: a **red-teamer** (operational
reading) + a **kernel/hypervisor researcher** (discovery reading). The same output, two readings. The output
= an attack-path.

### İ2 — Attack-path = a STATUS-LABELED chain (a statusless path FORBIDDEN)
- **a type-1 link** = a measured/validated edge → ENTERS the core.
- **a type-2 link** = a prediction, unvalidatable → does NOT ENTER the core, goes to the human.
- Every link is status-labeled. **A statusless path is forbidden** — otherwise epistemic-discipline collapses
  (speculation is mistaken for the measured; this is the lifeblood of the whole system — the same as the
  v0/g_A/MEASURED-CHOSEN distinction).

### İ3 — Two-loop architecture (the solution to speculation-leakage)
- **The TIGHT loop (measured):** type-1 → surface-value → path. Inside the core, a clean eigenform.
- **The LOOSE loop (speculative):** a type-2 prediction → the validation-gate → if it becomes type-1 → it
  enters the tight loop.
- Principle: **a prediction feeds the loop BUT not directly — via the gate.** Raw speculation cannot enter the
  measured-ground. (The loop-form of the KEV-as-input ban.)

### İ4 — Two scan-directions, strange-loop feeding
`surface→forward` (discovery) + `target→backward` (operation, like TTD-travel). They mutually feed → the
eigenform stabilizes. **BUT the feeding is ONLY from type-1** — speculation cannot leak in over-the-loop (the
guarantee of İ3).

### İ5 — THE TIME-GATE (resolves the human-dependency)
A prediction does not enter the core immediately; it **waits to materialize** (a CVE appeared on the surface /
g rose → it is measured → type-1). **The referee is reality, not the human.** This is the operational-form of
#Ç3 (when a chain materializes g_A moves). Trade-off: slow (months) — the human-gate was fast but made things
dependent. → the evolutionary solution (İ8).

### İ6 — ECHO-CHAMBER danger + perturbation
A strange-loop can turn into a self-CONFIRMING loop (AI early-favorite → path → surface↑ → more paths → echo).
**It cannot be audited from the inside** (Gödel-like: an echo-chamber looks internally-consistent). Solution:
perturbation FROM THE OUTSIDE — shake it and separate which fixed-point is real (holds) from which is an echo
(drifts).
- **Type:** random-re-seeding (MAIN — is the eigenform independent of the start) + adversarial-injection
  (complementary — does it filter a fake-signal). Ablation is tertiary.
- **Strength:** NOT fixed, SCANNED — the breaking-threshold is the metric (a high threshold = a robust
  eigenform; see dose-response).
- **Source:** automatic-continuous (baseline-health) + expert-triggered (deep-query).
- **The human-auditor IS ALSO perturbed** (human-echo-chamber risk — deliberately show a
  plausible-but-wrong prediction, does he approve it).
- ⚠️ **CC-FLAG (blind-spot, not hidden):** random-seeding shakes the *state* (initial-favorites), not the
  *operator* (the AI's judgment-function). If the pathology is in a systematic operator-bias ("a
  robust-echo") seeding DOES NOT CATCH it — at every seed it converges to the same wrong fixed-point.
  Candidate defense (open): **operator-diversity** (the same loop with different models/personas; a real
  eigenform is model-invariant). Also: the perturbation-verdict must be given by the CORE (deterministic),
  not by AI-judgment — *the judge cannot be the defendant*; and the perturbation generator must be
  outside-the-loop (if the loop's own AI generates it, it does not shake it toward its own blind-spot).

### İ7 — SELF-FULFILLING danger (CRITICAL, timeline-hostile)
The time-gate guarantee is **CONDITIONAL** — only if reality is independent of the prediction. In a used-tool
it breaks: the tool points at X → attention goes there → a bug is found → the prediction is "confirmed" (but
because of ATTENTION, not because of value). This is the **#Ç3-collapse** (without a control group the 84% was
deceptive — "84% on skip too"). In the low-user phase it is ASLEEP/invisible; it **ACTIVATES precisely when you
want full-autonomy at product-scale** (activation = the moment of maximum autonomy; the ordering is hostile).
- **Solution: held-out + base-rate, from DAY-1.** Independence is earned NOT with time but with a
  **control-test**; as the matching rises it is RE-EARNED. The low-user phase = a non-reproducible clean
  baseline (cannot be set up later).
- **Product = NOT "a mature autonomous tool"** → "a tool + PERMANENT self-audit". No full-autonomy; autonomy is
  continuously earned according to the matching-level.
- **Held-out LEAK-TIGHTNESS = a design-requirement** (if it leaks the control-group is contaminated, the
  measurement becomes meaningless).

### İ8 — The evolutionary path (the human is an auditor at first, then unnecessary)
Phase-1 human-assisted (**the human = the AUDITOR of the time-gate**, not merely an accelerator) → Phase-2
parallel controlled accumulation (ledger + held-out track-record) → Phase-3 becoming-independent **only once
the control-test is passed** (if the prediction holds even on surfaces it did NOT promote). "It matured" = "it
showed out-of-loop prediction-validity", NOT "it ran for N months".

### İ9 — THE TWO RED LINES
- (a) **Usage/engagement is NEVER fed to the gate** — the purest dirty signal (the user acts according to what
  the tool shows → circular). The same as the KEV-as-input ban. The gate stays strictly in reality (CVE+g),
  not in engagement.
- (b) **Irreducible-mismatch is measure-and-QUARANTINE, NO formula "fix".** The degree-normalize lesson:
  rescuing a dirty signal → drop/discount it. Held-out (the clean channel) is trustworthy; a
  promoted-confirms is SUSPECT until the difference is proven clean.

### #Ç4 (NEW OPEN MEASUREMENT) — the self-fulfilling coefficient
The **confirmation-rate difference** of promoted vs held-out, as a FUNCTION of user-scale (longitudinal). ~0 in
a clean-regime; if, as the matching rises, the promoted-confirmation inflates above the held-out's = there is
self-fulfilling. **If the gap widens, pull autonomy back.** Not solved at the desk; the prediction-ledger
(`ai_kolu/ongoru_defteri.py`) is read as data accumulates. Same status as #Ç1-3 (the system's first output).

## T4 — THE DATA-SUBSTRATE DECISION: generic-NVD → kernel-CVE-git (2026-07-18, a PHASE, researcher-approved)

> T4 was RE-FRAMED. Old: "add KEV/colocation to the existing-NVD" (tried → FAILED). New: "rebuild the
> substrate onto the mission". Order: (1) phase-approval ✅ → (2) SOURCE-VERIFICATION (FIRST) → (3)
> migration-design.

**FACT (measured):** Tiefenriss is still on Prozessfall `cve_raw` — 9333 CVEs, 100% NVD. The domain is
mission-ORTHOGONAL: kernel-vp 2% (61/2947); kernel-proper `linux:linux_kernel` = **25 surfaces, all CPE-LUMP,
subsystem-resolution 0**; the rest web-app-generic. → up-to-now it was tested in the WRONG-DOMAIN (the mission
= kernel-primitives, the corpus does not host it).

**T4-DOMAIN-FITNESS (the current-corpus) FAILED (pre-registered threshold `<33 underpowered / <20%-mission
mismatched`):** KEV is not in the corpus (external); the in-corpus weaponization-proxy is MSRC `detected`=1
surface / `more_likely+detected`=53 but **0% mission-domain** (all Windows/Azure) + **0/141 evaluated-subset**;
for colocation the commit-data is **STRUCTURALLY ABSENT** in `cve_raw`. → cleanly INSUFFICIENT. **Lesson:
domain-orthogonality came NOT FROM THE DATA but FROM THE SUBSTRATE-CHOICE** (generic-NVD is the wrong-corpus).
Not forced ("don't validate to the wrong-reality").

**DECISION — substrate-migration (a PHASE, not a task):** kernel-CVE-git (linux-cve, kernel-CNA 2024-02) is
mission-fit. It solves THREE of the four-blockers: (a) **granularity** = subsystem MEASURED from the commit
file-path (mm/net/drm), not keyword/CHOSEN → **the AU-1-lump-tension is naturally-resolved** (the lump is not
MANUFACTURED; one moves to a non-lump corpus — the "lump-opening-refusal" is STILL correct, the solution is
"measure, don't manufacture"); (b) **colocation** = in-tree same-commit (the red-team axis; the earlier
cross-product-red did NOT cover this — that was different-repo, this is same-repo); (c) **multi-year horizon**
(#Ç4/time-gate measurable; the 46d-blocker is lifted). IT DOES NOT SOLVE: the weaponization/exploit-dev axis
(git does not give in-the-wild → a separate source: syzbot-repro / exploit-db / public-LPE).

**Isolated (the reward of sealing-the-core):** the core is element-agnostic → the migration CHANGES ONLY the
adapter (surfaces / positions-g_A / params), it DOES NOT TOUCH the sealed core. The scope narrowing to the
kernel = MISSION-ALIGNMENT (web-app was always noise), not a loss. This is the logical consequence of the
"not-a-Prozessfall-binder / DB-proxy" correction.

**CONDITION — SOURCE-VERIFICATION BEFORE THE MIGRATION-DESIGN (the KEV-lesson: don't ASSUME the data, VERIFY
it):** the linux-cve-git real-schema: does commit→file→subsystem really exist · coverage ·
subsystem-assignment-reliability · how-many-surfaces it produces · is held-out-N sufficient (f=0.15).
**Migration-design note (researcher flag):** g_A hub-popularity (Spearman g_A-vs-degree 0.9113) must be
RE-CHECKED in the NEW edge-definition (file/subsystem-neighborhood) — the CPE-only-cleaning does NOT
automatically CARRY OVER; in a file-neighborhood there may be a different-hub-effect.

**SOURCE-VERIFICATION RESULT (2026-07-18, real-data git.kernel.org/vulns.git — NOT AN ASSUMPTION):** POSITIVE,
with one real gap. ✅ Accessible + the CVE-5.1 schema is real. ✅ **Scale:** 2024=**3063**, 2025=2668, 2026=2350
kernel-CVEs, 2019–2026 → held-out-N (f=0.15) more than sufficient (≫33). ✅ **100% mission-domain** (all
kernel). ✅ **Subsystem-assignment RELIABLE:** `affected[0].programFiles` is **12/12 FULL** in the sample
(net/tls, kernel/bpf, drivers/net, mm, fs, arch/...), multi-subsystem only ~17% (the assignment-rule:
primary-file / the main-file of the fixing-commit) → the lump dissolves MEASURED. ✅ **colocation:** `versions`
= vulnerable→fixing commit-pairs + fix-commit SHAs → in-tree computable. ⚠️ **REAL-GAP — NO CWE (0/12 in the
sample):** the kernel-CNA assigns no CWE (`problemTypes` empty). Surface=(CWE,subsystem) AND the v0-ruler works
with a CWE-input → kernel-CVE-git DOES NOT GIVE the CWE-half. **Migration candidate-solution:** get the CWE from
the NVD-JOIN (over cve_id; NVD enriches kernel-CVEs with CWE — the existing 25 kernel-surfaces in cve_raw prove
this). **BUT THE JOIN-COVERAGE must be measured** (the NVD backlog → maybe not all of 3000/year is enriched) =
the first measurement of phase-3. This gap is what the "don't-assume-the-data" discipline catches — had we
assumed (CWE,subsystem) and designed the migration, we would have hit a wall.

**JOIN-COVERAGE MEASUREMENT (2026-07-18, NVD API × vulns.git, n=40 sample):** CWE-source=NVD-join confirmed (a
mechanical-reference, stays-MEASURED; fix-text-inference REJECTED=derivation, a CWE-less-surface
REJECTED=kills-v0). Pre-registered threshold `>70% clean / 40–70% marginal / <40% stop`. **Result: NVD-CWE
usable-rate 31/40 = 78% → the CLEAN-band (point).** By year: 2021 75% · 2023 50% · **2024/2025/2026 88%** — the
expected recency-backlog was REFUTED (the post-CNA years are the BEST; the single-point 26581→noinfo was
unrepresentative, sampling+pre-registration prevented over-generalization). NVD-absent 0, weakness-absent 0;
the only failure is `noinfo/other`. **HONEST CAVEATS:** (i) small+head-sampled (not-random, may be optimistic);
Wilson-CI(31/40)≈[60%,86%] → the lower-end TOUCHES marginal → the FIRST job of the migration-build must be a
full-universe coverage-measurement (n=40 is a green-TREND, not a definite-number). (ii) the surface-N was
estimated (~hundreds, held-out-N comfortably >33) NOT MEASURED (a full-join is required). (iii) the
closed-set-CWE rate was not measured (a set-outside CWE builds-a-surface-but-boundary-rejects, like CWE-121) =
phase-3. **VERDICT (n=40): 78%>70 → it looked clean — BUT A MULTI-AGENT WORKFLOW CORRECTED THIS (below).**

**THE MULTI-AGENT T4-DESIGN WORKFLOW (2026-07-18, 10 agents: 4-measurement ∥ 5-adversarial-refutation ∥
synthesis; run wf_3a90419c):** The first real fan-out. The adversarial-pass CORRECTED the n=40-optimism + caught
a concrete g_A-error that would not be found solo.
- **CWE-JOIN: 78% → REALLY 61% (MARGINAL, NOT-clean).** The n=40 head-sample was optimistic. Full-census: the
  NVD-linux_kernel virtualMatch universe (18,552) ≠ the kernel-CNA vulns.git (12,569) — a naive-ratio gave
  2024-26 111%/126%/111% (>100%=proof of separate-sets). The only-valid measure = the CVE-ID intersection:
  **usable-CWE-join 61.0%** (all-year) / 61.2% (2024-26). The ceiling conditional-on-NVD-presence is ~68% —
  even if the backlog is resolved, BELOW the 70%-threshold (noinfo/Other a permanent-ceiling). But the
  covered-subset is mission-aligned (72% memory-primitive: CWE-476/416/401/787/125/362). → **a surface
  CANNOT BE BUILT CWE-keyed; SUBSYSTEM-keyed + CWE-an-optional-node-attribute, the ~39% CWE-absent is
  left-OPEN (the NO-DERIVATION/NO-FORCING principle).**
- **g_A HUB IS REINCARNATING + the hub-checks are BLIND (the most serious, PROVEN at real-N=5731).** The
  adversarial-agent built a new IDF-PageRank g_A on the real-data: the highest g_A = `include/linux` (a
  header-namespace, NOT an attack-surface), ~3× the #2. IDF DOES NOT de-hub at the total-edge-mass level (a
  god-file's mass ~n²/log n; smb2pdu.c is 182× an n_f=2 edge). Both pre-registered detectors are
  FALSE-NEGATIVE: Spearman(g_A,degree)=0.690<0.85, Spearman(g_A,subsys-size)=0.274. The CPE-lump → reincarnates
  as a header-bridge-lump; the 5-step hub-check DOES NOT CATCH it. → the hub-check must be EXTENDED with a
  header-bridge-test (exclude include/*.h / header-IDF); until it passes on real-data g_A is untrustworthy.
  Fixable, not fixed.
- **colocation: THE STRUCTURAL-claim HOLDS** (dense/not-degenerate/subsystem-consistent: ksmbd 100%, f2fs
  96%), **but "it feeds the red-team realization-axis" WAS NOT CONFIRMED** (an audit-bias: the hot-files = the
  most-fuzzed subsystems → it tracks where-attention-already-is). fix-SHA-sharing is DEAD (0.1%) → only
  file-colocation.
- **held-out-N WAS NOT MEASURED at the SURFACE-granularity:** at the CVE-granularity N~741-1151 (>33
  comfortably); but surface=(CWE,subsystem), after the 61%-join + heavy-tail + singleton-pruning, if the
  distinctly-evaluable-surface drops to 100-200 then 0.15×S=15-33 <33.
- **SYNTHESIS: GO-WITH-CONDITIONS (medium-confidence).** The substrate is validated (clonable, 12,569 CVEs,
  programFiles 100%, colocation-dense); but 2 of 3 axes did not pass adversarial-clean (CWE-marginal +
  g_A-hub-reincarnate). **BUILD-STEP-1 = FULL-CENSUS SURFACE-COUNT + MCAR-TEST** (it solves 3 open-risks
  at-once: distinct-surface-N under ≥1/≥3/≥5-CVE-pruning → held-out-power; per-subsystem CWE-coverage → is it
  MCAR or a structural-gap). The B-agent (subsystem-measurement) errored on StructuredOutput — but build-step-1
  already covers it. Note: this is the multi-agent-adversarial form of "don't-assume-the-data" = it corrected
  the n=40.

**THE BUILD-STEP-1 WORKFLOW (2026-07-18, 10-agent: PREP + 4-condition-measurement∥refutation + synthesis; run
wf_6c31f904).**
PREP census: 8081 CVEs (2024-26), 573 subsystems, 5427 files, **CWE 61.2%** (it exactly-repeated the
previous-61%), 38.8% CWE-absent-open. **FOUR CONDITIONS — synthesis: GO-WITH-CONDITIONS (1-met / 2-partial /
1-NOT_MET):**
- **C1 surface-N/held-out = MET (at the ≥3-operating-point)** but not-universal (partial): S=2280/652/347
  (≥1/≥3/≥5), held-out=342/98/52. Adversarial: at ≥5-real-CWE held-out is **32.2<33** + it collapses on a
  top-dir-lump → LOCK the ≥3-operating-point (held-out 98, >33 in all-slicing), do not lean on the ≥5-cushion.
- **C2 MCAR = PARTIAL-contained:** MCAR is DEFINITELY-REJECTED (χ² z=24σ; the CWE-absence is
  structurally-clustered, thin at arch/x86 32% / crypto 39% / bpf 48%). BUT **the KEY-axis (subsystem/file, the
  g_A-edge-base) is 100% present** (0/8081 absent), the gap is ONLY in the optional-CWE; the mission-subsystems
  (net/mm/fs ~60%) are not-blind → containment adversarial-SURVIVES.
- **C3 g_A reliability = NOT_MET (the main finding):** header-cleaning DOES de-lump (include/linux/net
  disappear, Spearman 0.853→0.55) — BUT the problem is DEEPER than the header: **SPARSITY.** 85% of CVEs are
  single-file, 5.5% multi-subsystem → **51.7% of the subsystems are isolated-singletons (PageRank=uniform-floor),
  26.6% of the CVEs are INVISIBLE to g_A**; de-lumping WORSENS the fragmentation (62% isolated, giant-component
  22%). The adversarial tried the 'mixed-granularity keying-error' argument → at dir-level re-keying the
  isolation is 50.6% (unchanged) = the sparsity is SUBSTRATE-level, SURVIVES. → in the 2024-26 window the
  co-programFile-g_A is either a single-namespace-star or dust; PageRank is meaningless on the surface. g_A =
  the value-gate-input (v=v0·g_A) → it is load-BEARING.
- **C4 colocation-audit = PARTIAL-quarantined:** the signal is real+distributed+forward-stable (41-47% remains
  when the top-100-files are removed; Spearman-forward 0.40) BUT the audit-confound is STRONG (the
  top-colocation = the full fuzz-magnet roster ksmbd/bpf/netfilter) + it is BLIND to ~54% of the fresh-surface
  → it can be used only as an "attention-normalized sustained-yield prior", NOT a raw red-team-axis.
**OPEN (before build-2):** (1) collapse the mixed-altitude surface-key to a single-dir-level; (2) **solve the
g_A-SPARSITY — the main-decision: is it a window-artifact (does the full 2019-26/pre-2019 history connect it)
or a fundamental-limit (file-co-occurrence a wrong-edge / are kernel-bugs genuinely-isolated)** → a targeted
measurement; (3) does the primary-file-only reporting-convention under-show co-occurrence; (4) lock the
≥3-point, never-derive the optional-CWE; (5) deconfound the colocation with independent-fuzz-data + quarantine;
(6) the audit-bias: fix-or-declare-a-known-blind-spot.

**THE C3 g_A-SPARSITY DIAGNOSTIC WORKFLOW (2026-07-18, run wf_8d14ad45; PREP full-history 12569 CVEs 2019-26).
DIAGNOSIS: MIXED.**
Three-hypotheses were distinguished (the W1-agent errored but PREP+W4 measured the window anyway):
- **(a) WINDOW-artifact = REFUTED.** The single-file% is STABLE across years 84.5-87.7% (overall 85.6%); the
  3→12-year isolation only shifts ~2-4pp. Time-independent.
- **(b) REPORTING-artifact = REFUTED+CLOSED.** aff[0].programFiles == the full-affected union (0
  under-count/12569); a distinct 60-CVE sample matched 60/60 bidirectionally with the GitHub-mainline-diffstat;
  **the bippy-source (tools/cve_utils) builds programFiles exactly from the `git show --name-only` diffstat** →
  faithful. The Anubis-blind-spot was resolved.
- **(c) FUNDAMENTAL = SURVIVES for the co-occurrence-substrate:** kernel-fixes really are file-local (85.6%
  single-file, confirmed).
**BUT 'mixed' because — the main correction (adversarial):** the degeneracy of the co-occurrence-graph ≠ "g_A is
weak in the kernel". **I OPERATIONALIZED g_A WRONGLY: WITHIN-CVE co-occurrence (shared-file in the same-CVE).
But g_A's ORIGINAL definition = HUB-POPULARITY = CROSS-CVE recurrence** — that is ABUNDANT in the SAME
substrate: 37.6% of files recur in ≥2-CVEs (verifier.c=66, smb2pdu.c=61, nf_tables_api.c=60 CVEs); 72.5% of the
single-file-CVEs touch a recurring-file. So the sparsity is both REAL (for the co-occurrence-construction) and
an ARTIFACT (the co-occurrence+fine-granularity CHOICE). The isolation-magnitude is granularity-dependent
(top-dir 9.5% / 2-path 49% / file 53.8%) → a single-number is not canonical.
**VALUE-COMPOSITION (v=v0·g_A, the core UNCHANGED):** in the kernel, value is **v0-DOMINANT.** v0
(CWE-primitive-family) is well-distributed+discriminating (UAF/OOB-write vs null-deref/leak are
value-different). co-occurrence-g_A is DEAD; hub-popularity-g_A is DENSE BUT size/churn-confounded — **and NOTE:
this is exactly the hub-popularity pattern that the old-g_A-cleaning (CPE-only, the Spearman-0.911-degree-artifact
removed) had removed**; still, in the kernel "a frequently-hit-file=a hot-attack-surface" (verifier.c) may be
partly-legitimate (different from the old cross-product-CWE-noise) → without a value-ground-truth (KEV is
domain-orthogonal) it CANNOT BE VALIDATED. **DOMAIN-LESSON: in the kernel it is v0-weighted, g_A a
bounded-modifier (co-occurrence-dead, hub-popularity-unverifiable-suspect) — not a migration-error, but a
domain+construction lesson.**
**SYNTHESIS: the fetcher = GO-WITH-CONDITIONS.** The value-uncertainty that justified the 'hold' is
sufficiently-resolved: v0 works+is-discriminating; co-occurrence-g_A is dead-diagnosed (no wasted-effort in the
build); v0 and hub-popularity consume the same-substrate (the fetcher is not wasted). **g_A-economy:** DO NOT
SEND co-occurrence-g_A; connected-core-centrality + g_A=1.0-neutral for the isolated/tail (so the
degenerate-floor is NOT PENALIZED); a v0-weighted-mode (v0 primary, g_A a bounded-multiplier); remove the
include/-header-artifact; GATE the hub-popularity-weight on a held-out-value-validation (is-it-churn-or-value).
**Open (build-2):** hub-popularity-g_A as a value-signal is UNTESTED (the primary-open); code-structure-g_A
(call/include-graph, dense in the kernel but no-census-data) is a separate-path; v0's own 39%-coverage-gap +
v0-absolute-correctness were not validated.

**THE syzbot REALIZATION-SIGNAL WORKFLOW (2026-07-19, run wf_266ea970; PREP 7230 fixed syzbot-bugs, the dashboard
NOT-gated).**
**VERDICT: MIXED / the semantic-loop is QUARANTINED-openable / in the migration realization=QUARANTINE.** For the
first time a realization-candidate did NOT come out ORTHOGONAL (unlike the KEV failure). Four-dimensions:
- **S1 overlap = VIABLE-survives.** syzbot-found ~17% (GitHub commit-message grep, not network-verified) /
  **10.9% SHA-floor (879 CVEs, reproduced).** **197 subsystem-surfaces / 492 (sub,CWE) → >>100 overlap.** The
  CRITICAL adversarial-test: the fuzz-bias signal does NOT WHOLLY-determine it → **corr(subsystem-volume,
  syzbot-rate)=-0.096** (~zero); drivers/net (the largest, 1024 CVEs) is only 6.7% syzbot-linked, small
  mountable-fs's are ~50% → syzbot = an ORTHOGONAL-REACHABILITY-axis, NOT the hub-popularity-axis on which g_A
  died.
- **S2 time-direction = VIABLE-survives.** 0/1038 retroactive; crash→fix→CVE structurally-clean (syzbot
  leading); the forward-flow ~43-52/month with no-decay → sufficient at the 180d-horizon. Residual: the
  intra-year lead-time is thin (n=8); the measurement is retrospective (not a live-prediction-test).
- **S3 fuzz-bias = MARGINAL-partial.** The bias is REAL+GLOBALLY-DOMINANT (a HOT-subsystem is 58%-CVE-mass but
  96.4%-syzbot; reachable-vs-hardware 19.3×; drivers/net 1630-CVE→2-syzbot). BUT it is separable (within-HOT
  Spearman 0.68, 0.47 with size-controlled). Residual: 43% of syzbot is pre-2021 → the 0.68 may be a
  STATIC-attention-prior (NOT forward-realization); the shared-churn-confound was not resolved.
- **S4 domain+type = VIABLE-partial.** syzbot is WITHIN the mission-domain (46.6%-core/62.6%-ext) — UNLIKE the
  KEV-orthogonality. HIGH-primitive is ~40% a plurality ('mostly-WARNING-noise' was REFUTED). BUT a refuter:
  the quality-signal is ~0 (the HIGH-rate in-mission is 38.3% ≈ out-of-mission 40.7%) → the 24.6%-domain-alignment
  is a fuzz-VOLUME-artifact → **coverage-viable-BINARY-only, quality-domain-aligned-NO.**
**SYNTHESIS:** syzbot = a domain-fit, high-precision, POSITIVE-only, EVENT-based (İ9a-honorable,
never-intensity/ranking) realization-CUE — usable only in **syscall-REACHABLE subsystems**; hardware-bound COLD
~42% (drivers/net+gpu included) is QUARANTINE→to the human-arm. The semantic-loop is **QUARANTINED-openable:** a
reachable-zone → machine-#Ç4; a hardware-zone → an A-mode-human-referee. A minority-cue (~17%/11), its absence
is uninformative. **Open:** 17.5% was not network-verified (the 11%-floor is confirmed); the 0.68
static-prior-or-forward was not resolved (the census.jsonl SHAs are 2024-26-only, temporally-disjoint); the
realization-proxy="got-a-CVE" ≠ "was-exploited" (tier-mixed: 421-LOW vs 349-HIGH).

**═══ PRE-T4 RESEARCH COMPLETE — the FULL MAP of the kernel-substrate (2026-07-19) ═══**
The substrate (kernel-CVE-git): ✅ real/mission-fit/clonable. The surface (subsystem-keyed): ✅ held-out-power at
≥3. v0 (CWE-primitive-value): ✅ discriminating, 61%-coverage (39% CWE-open). g_A (graph-position): ⚠️ WEAK
(co-occurrence-dead, hub-popularity-unverifiable) → a v0-dominant-domain-lesson, g_A a bounded-modifier.
colocation (red-team): ◐ quarantine.
**realization/#Ç4 (syzbot): ◐ QUARANTINED — the semantic-loop PARTLY-closes** (reachable-zone machine,
hardware-zone human).
The DIRECTION is confirmed (the migration PRODUCES-value: a real-surface + partial-realization, which
generic-NVD could never give). NEXT: the build-2-decision.

**THE g_A CROSS-DOMAIN HYPOTHESIS WORKFLOW (2026-07-19, run wf_e8a598a3; 4-domain 1325-CVEs,
three-artifact-controlled).**
The researcher-reframe: g_A is weak in Linux-only because the scope is narrow; in broad-low-level it comes out
cross-linked. **VERDICT: REFUTED — v0-DOMINANT-PERMANENT (even in broad-scope).** Value is v0-dominant in ALL
three low-level-layers (kernel/hypervisor/hardware); there is NO g_A-rich-hardware-stratum.
- **X1 kernel↔kernel = artifact-only.** Real-cross-edge 0: ALL 39 shared-CVEs are Adobe-Flash
  cross-platform-userspace (NOT-kernel!); the only-remaining link is the excised-CWE-hub. (Caveat: the
  linux-census is refs/desc-LESS 0/450 → the coordinated-advisory channel cannot be measured =
  absence-of-evidence.)
- **X2 kernel↔hypervisor = MIXED — the ONLY real-artifact-cleaned seed.** 9 co-listed low-breadth CVEs; 2 of
  them are kernel.org+xenbits DUAL-referenced coordinated-advisory (the cleanest real-mechanism-signal in the
  dataset); drivers/xen/*.c paravirt lives in the Linux-tree (the guest-host interface). The real-peak of the
  gradient is here — NOT in HARDWARE, but in the INTERFACE.
- **X3 microarch = MIXED, breadth-inflated.** Your artifact-b was CONFIRMED+LOAD-BEARING: 91.7% of the
  affected-inflation is intra-hardware SKU-enumeration (0 cross-layer-edges); only 2.56% cross-software.
  **BREADTH ≠ BRIDGING:** the most-inflated CVEs bridge the FEWEST layers (LVI 1321-affected→0 software;
  Meltdown 209→0). ~50-58% phantom (microarch-by-keyword, with-no-hardware-endpoint). After IDF+phantom-cleaning,
  the real hw→linux idfSum 6.84 = ~**21× BELOW** the hypervisor-base of 146.4.
- **THE GRADIENT = FALSE.** The three-artifacts were confirmed: (a) the CWE-hub suppresses the kernel↔kernel-base,
  (b) the affected-list-breadth inflates the microarch-peak, (c) the raw-gradient = the composition of a+b. The
  cleaned-shape is **RISE-then-FALL** (the peak at the guest-host-interface), NOT a monotone-hardware-rise. (A
  4th confound: the refs/desc-coverage-asymmetry, linux 0/450 vs hypervisor 400/400.)
**THE DOMAIN-LESSON IS FINAL:** in low-level-offensive, value is INTRINSIC (primitive-type=v0),
NOT-RELATIONAL (graph-position=g_A) — and this is NOT a scope-artifact, but the-real-property-of-the-domain.
**The one real cross-domain-relation = INTERFACES/CHAINS** (guest-host, the place where code is
physically-bridged), captured with coordinated-advisory/cross-reference (NOT the CWE/affected-list) — and it is
thin. This = the AI-arm's TRANSITION-atom-region (predicted-chains), not the measured-g_A-region.
**Architecture:** v0-dominant (all-layers), g_A a bounded-modifier (the scope did not rescue it), relation =
chain-interface (the AI predicts it), realization = syzbot-quarantine. The value-architecture is FULLY-MAPPED.
**META:** your artifact-b-control (the affected-list-inflation) prevented a false-confirmation — without it the
microarch-breadth would have been wrongly-confirmed as "g_A-rescued". The strongest evidence of the
adversarial-mode + researcher-in-the-loop.

## Next (open, the decision to the researcher)
- **THE AI ARM BUILD:** the İ1-İ9 principles above + the prediction-ledger schema are ready; the build is a
  separate phase (not yet started).
- **#Ç3:** deferred until multi-year history / time-stamped embeddings arrive (the code is ready, a data
  constraint).
- **v0 declaration approval:** the `CETVEL_BEYANI.md` §3 ranking + §5 deviations (info-leak added, race
  mismatch) await researcher approval.
- **Making the Prozessfall-binding decision permanent:** the DB read-only proxy works; a permanent data
  pipeline (live fetch, embedding regen cadence) is a separate engineering round.
- **Keyword coverage:** the kernel-keyword list can be extended (distro CPEs, more subsystems).

---

## PERMANENT RULE — THE CODE LANGUAGE IS ENGLISH (2026-07-19, set by the researcher)

From now on **ALL code** is written in English: function/variable/class/enum/file names, **docstrings**,
in-code string constants (enum-values, dict-keys, provenance/reason strings, test-labels, report-text).
**EXCEPTION (may stay Turkish):** inline conceptual `# comments` (the researcher's language of thought) +
the design-documents (`.md`). The ideal style: English code + Turkish conceptual-comments (`# MEASURED =
ölçüldü`).

This is a convention-correction; **the behavior DOES NOT CHANGE, only the names.** Scope: every NEW file
starts in English. The sealed packages (`cekirdek/`, `ai_kolu/`, `adapter/`) + folder-names (`veri/`→data,
`cekirdek/`→core, `kaynaklar/`→sources) are UNTOUCHED FOR NOW (regression/import-risk; a separate-careful round,
probably with the Rust-port).

**The `veri/` package was TRANSLATED (2026-07-19), tests 33/33 + regression preserved.** The canonical
term-mapping is in the memory `code-language-english.md`. Summary: Statu→Status · ÖLÇÜLDÜ/TÜRETİLDİ/AÇIK/KARANTİNA→
MEASURED/DERIVED/OPEN/QUARANTINED · Oznitelik→Attribute · olculmus()→measured() · evril()→evolve() ·
BirlesikKayit→MergedRecord · KismiSurface→PartialSurface · birlestir()→merge() · topla()→aggregate() · Zon→Zone ·
DisiplinHatasi→DisciplineError.
