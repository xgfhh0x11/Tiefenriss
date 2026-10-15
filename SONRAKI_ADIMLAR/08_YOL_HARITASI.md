# 08 — ROADMAP + PRIORITY MODEL + ACTIVE TODO (2026-07-16)

> This file is the ACTIVE task-list after the calibration phase closed + the rationale for HOW WE
> PRIORITIZED IT. The goal (researcher's request): preserve not the result but the CONTEXT — so
> that looking back one can see "why this order, at which threshold did we turn back."

## ⟢ PHASE SEALED (2026-07-22) — see `09_KAPANIS.md`
The value-substrate + connected-eye + open-time-gate were built. The binding constraint is now TIME (realization comes months-later).
**When you return:** `09_KAPANIS.md` §4 → refresh-census → `veri.wire_core` → `realization_detector` → `confirmation_gap()`.

## Phase status
- ✅ The calibration phase is CLOSED (g_A=CPE-only, hub-popularity removed).
- ✅ The AI-arm PRINCIPLES were recorded (`PoC_BULGULAR.md` §AI KOLU MİMARİSİ, İ1-İ9 + #Ç4).
- ✅ The prediction-ledger SCHEMA was set up (`ai_kolu/ongoru_defteri.py`, empty, held-out, leak-proof).
- ⏳ Next: the prioritized TODO below.

## PRIORITY MODEL (why this order) — 3 independent lenses, all converging

Three candidate tasks: **A**=AI-arm build-decompose · **B**=cheap foundational-debts · **C**=external data acquisition.

**Weighted score:**

| Criterion (weight) | A | B | C |
|---|---|---|---|
| Under-dependency/unblocks (.25) | 3 | 5 | 2 |
| Cheapness (.25) | 3 | 5 | 1 |
| Leverage-NOW (.20) | 5 | 3 | 2 |
| Risk-reduction (foundational-debt) (.20) | 2 | 5 | 2 |
| Window/irreversibility (.10) | 3 | 2 | 1 |
| **Total** | **3.20** | **4.30** | **1.65** |

**Lens 1 (topology):** the v0 ruler (the race-mismatch in B) is the value-ground of the AI arm; C validates
A's output (no arm → nothing to validate). → B → A → C.
**Lens 2 (ROI):** B is tiny cost + high unblock; C is high cost + blocked, leverage deferred. → B → A → C.
**Lens 3 (window):** the only closing-window is İ7 clean-baseline; the schema was handled on day-1, FILLING requires the arm (A) →
A is slightly more time-sensitive than C. C has no window right now. → B → A → C.

**The threshold we turned at (recorded context):** the temptation of "A-first for momentum" was REJECTED — B is so cheap
(DB ~10min + race decision ~5min) that deferring it doesn't buy any meaningful A-progress; and B2 fixes a WRONG value in the ruler
(race 0.80 vs declaration MEDIUM) — if left unfixed the AI arm inherits it (a "garbage in→garbage out" violation).
So B comes first not only on ROI but also on epistemic-hygiene.

**B refined:** not a single block, two halves blocked differently:
- **B1** (DB-portability) = MY task, unblocked → immediately.
- **B2** (the v0 §5 decision) = a RESEARCHER decision; it blocks A's *build*, but NOT its *decompose* (the race number
  only comes into play when the arm computes value) → while B2 waits, A-decompose can proceed in parallel.

## ACTIVE TODO (prioritized)

- [x] **T1 — B1: DB-path portability** · owner: CC · ✅ DONE (2026-07-16)
      `surfaces.py DB_DEFAULT` → TIEFENRISS_DB env override + a path anchored to the repo root. Verified: the path resolves,
      override works, regression 7/7, run_poc connects to the DB. See `07_kucuk_isler.md` §7.1.
- [x] **T2 — B2: the v0 §5 decision** · owner: RESEARCHER · ✅ DONE (2026-07-16)
      (a) race CWE-362 → **0.80 STAYED, the declaration was updated to HIGHEST** (mission-aligned: race-to-UAF/double-fetch
      is a premier primitive; the contradiction was resolved by raising the declaration, not lowering the ruler). (b) info-leak → **APPROVED**
      (200=0.75, 908=0.70, 125=0.70). The ruler.py FLAG was removed, CETVEL_BEYANI §3/§5 updated, regression 7/7.
      → The value-ruler is now consistent; the AI-arm BUILD ground is clean.
- [~] **T3 — A: AI-arm build-decompose** · owner: CC+researcher · IN PROGRESS
      Skeleton accepted (A1 measured-substrate → A2 AI-generator → A3 loop+safety; "measured first, speculative later").
      **A1 module-1 realization-detector: DESIGN DONE** (`ai_kolu/A1_realization_detector_TASARIM.md`) — 4 decisions
      bound (primary=core-tier-crossing · threshold=existing tier-boundary, no new-anchor · LAPSED mandatory · horizon
      nominal-SEÇİLDİ, direction-flexible). Schema implemented (LAPSED/horizon/tier_at_creation/mark_lapsed), regression 7/7.
      A1 module-2 design closed: assignment=seeded-random (RCT-control), unit=SURFACE (attention-free baseline),
      f=15% SEÇİLDİ (Poisson-power note), SEED=global-constant-INVARIANT (if changed the baseline resets). #Ç4 asymmetric.
- [x] **T5 — A1-BUILD (FIRST REAL CODE ROUND)** · owner: CC · ✅ DONE (2026-07-16)
      Modules: `ai_kolu/defter_config.py` (f=0.15, seed-invariant, horizons) · `dolum.py` (exposure=surface-unit
      seeded-random sha256 + record: horizon/tier_at_creation snapshot) · `realization_detector.py` (tier-crossing
      → promote/lapse, deterministic, no AI, verdict from the core) · `adapter_bridge.py` (live {sid:tier}). Test:
      `test_a1.py` **7/7** (held-out fraction=0.150), core regression **7/7**, end-to-end bridge verified, production
      ledger EMPTY. Detector is pure (current_tier dependency-injected).
- [~] **T6 — A2 (AI-GENERATOR) design** · owner: CC+researcher · IN PROGRESS (2026-07-17)
      Discovery + sense-making + attack-path generation (İ1) via VİZYON multi-lens discovery. LLM-operator. Produces Type-2
      predictions → dolum→detector→#Ç4. Skeleton + 6 decisions sealed: `A2_ai_generator_TASARIM.md` (extensible-
      lens+technical-basis · MODERATE-K4 [multi-lens≠operator-diversity; robustness=lens-vs-reality #Ç4] · 5-field-
      schema+provenance · energy=SEÇİLDİ · source-surface single-anchor). **A2.2+A2.3 detail:** `A2m23_mercek_sinir_TASARIM.md`
      — central principle: the boundary tests FALSIFIABILITY, not conventionality. **4 sub-decisions SEALED (2026-07-17):**
      (1) signal=THREE-WAY (falsification-method-definable; now/pending-detector/rejected + 3 guards) · (2) lens-schema
      +budget-priority · (3) rejection-log structured-summary+reason · (4) vulnerability-class=CWE-closed-set. Schema += measurement-category.
      **A2.4+A2.5 (assembly+publication) detail:** `A2m45_montaj_yayim_TASARIM.md` — central principle: **GATE the atoms, PRESENT the path**
      (per-link status; a path does not realize, its links do). Chain=exploit-primitive-logic+hop-status · path=separate
      registry (prediction-id ref) · pending-detector=ledger-view · A1 schema-extension (defaulted, compatible). 5 open
      sub-decisions. **A2.4+A2.5 SEALED (2026-07-18):** transitions are a SEPARATE Type-2 atom (both node+edge are gated);
      path=atom-chain, annotation is the weakest-atom (transition included); path-registry separate; İ3 Type-1-feed deferred to A3.
      A2 DESIGN DONE (A2.1–A2.5).
- [x] **T7 — A2-BUILD (2-PASS)** · owner: CC · Pass-1 ✅ + Pass-2 ✅ DONE (2026-07-18)
      **Pass-1 (deterministic scaffold + ADVERSARIAL stub):** schema-extension (`ongoru_defteri` +A2 fields, defaulted,
      A1-compatible) · `lens_registry` (6 lenses, extensible, energy-mapping) · `boundary` (THREE-WAY+3 guards+CWE-closed-
      set) · `yayim` (dolum+single-anchor+exposure-blind+rejection-log) · `montaj`+path-registry (weakest-atom, transition included) ·
      `stub_operator` (adversarial: 8 rejection-branches+5 admit) · `test_a2` **8/8** (anti-green-deceptive: 8 rejections actually occurred).
      A1 7/7 + core 7/7 preserved, ledger EMPTY.
      **What Pass-1 PROVED:** deterministic epistemic-plumbing (boundary-routing, single-anchor, exposure-blindness, categories,
      weakest-link, schema-compatibility). **What it did NOT prove (the Pass-2 burden):** free-text→typed-schema projection + label-HONESTY
      (can the LLM leak by mislabeling signal_kind) — this can only be tested with a real operator + reality-gate.
      **Pass-2 = a real Claude operator** (multi-lens separate-transition + transition-logic; the claude-api reference is to be read).
      **VİZYON-ALIGNMENT DONE (2026-07-18, PoC_BULGULAR §ÇOK-ÖLÇEKLİ GÖRÜŞ):** the two-kinds-consistency meta-principle +
      AU-1 CLOSED (strategic-eye A / gaze-filters B / cell-boundary) + AU-2 SCOPE CLARIFIED (backward=MEASURED/A3,
      forward=operator-tier2 → the operator is set up ONCE) + the NET-BUG fixed (yayim skip-default → reject, test_a2 8/8).
      → Pass-2 is now DESIGN-UNBLOCKED; it only awaits reviewer BUILD-approval.
      **PASS-2 BUILD ✅ DONE (2026-07-18):** `llm_operator.py` (real Fable-5 operator + Recorded/Anthropic backend
      + parser) + CEILING-GUARD (`boundary.py`, AU-1 operational). `test_pass2` 6/6; core/A1/A2 preserved; ledger EMPTY.
      Finding: the boundary catches the STRUCTURAL-fake (none/closed-set/ceiling-mislabel) but NOT the SEMANTIC-lie → only
      #Ç4/realization judges it (the reason for held-out day-1). #Ç4 cannot run on a static corpus → PLUMBING+structural proven, the semantic-loop is post-T4.
- [~] **T4 — DATA-SUBSTRATE MIGRATION (PHASE)** · owner: researcher+CC · effort: high · ONGOING (2026-07-18)
      RE-FRAMED: not "add KEV to NVD" (attempted→FAILED, domain-orthogonal) → "rebuild the substrate for the mission"
      (generic-NVD → kernel-CVE-git). Measured: the existing corpus is mission-orthogonal (kernel-proper 25 CPE-lump
      surfaces, subsystem-0; web-app-generic). The migration solves the three-blocker (granularity=measured-subsystem / colocation=in-tree /
      multi-year-horizon), closes the AU-1-lump-tension, does not touch the core (adapter-isolated), aligns with the mission. See PoC_BULGULAR
      §T4. **ORDER: (1) phase-approval ✅ → (2) SOURCE-VALIDATION ✅ → (3) MULTI-AGENT DESIGN-WORKFLOW ✅ (2026-07-18, 10-agent,
      adversarial) → (4) BUILD-STEP-1 (full-census, decision-with-researcher).** Workflow verdict: GO-WITH-CONDITIONS. The adversarial-pass
      corrected n=40: the CWE-join is really 61% (MARGINAL, not clean) → surface SUBSYSTEM-keyed + CWE-optional-attribute
      (~39% leave-open). The g_A-hub REINCARNATES at real-N=5731 (include/linux header-lump) + the pre-registered hub-checks are false-negative
      → must be extended with a header-bridge-test. colocation is structurally-standing but "feeds-realization" was not verified. BUILD-STEP-1 =
      full-census surface-count + MCAR-test (held-out-power + structural-gap). Full record in PoC_BULGULAR §T4/workflow. B-agent error (build-1 covers it).

- [~] **T8 — DATA-LAYER BUILD (FIRST REAL BUILD, PHASE)** · owner: CC+researcher · effort: high · Pass-1 ✅ (2026-07-19)
      The T4-strategy-round converged on 3-structural-moves → build a **status-typed, source-agnostic data-layer** (NOT "write-an-adapter").
      Approved structure: (1) status-typed-source-agnostic-layer [foundation] · (2) Python-stabilize→Rust-incremental [language, avoid early-Rust-lock]
      · (3) domain-profile · (4, CC-addition) **status-typed-RECORD** = the deep form of Move-1 (source-agnosticism is not enough;
      the record MUST CARRY the epistemic-status, otherwise the leave-open/quarantine discipline is lost as it leaks). + two-role-source, refs-load-bearing.
      **Pass-1 ✅ DONE (2026-07-19), the `veri/` package:** `statu.py` (Statu ÖLÇÜLDÜ/TÜRETİLDİ/AÇIK/KARANTİNA + `Oznitelik`
      value+status+provenance+HISTORY; the `olculmus()` barrier; `evril()`=time-gate-data-state; `DisiplinHatasi`) · `kayit.py`
      (TWO-ROLE: SurfaceKaynak→KismiSurface / RealizationKaynak→RealizationOlayi; Surface refs+zone first-class; Zon; DomainProfil)
      · `birlestir.py` (status-PRESERVING join, confidence-order, an AÇIK→ÖLÇÜLDÜ join-promotion is written back to history) · `stub_kaynak.py` (adversarial)
      · `test_pass1.py` **23/23** · `TASARIM.md` (language-neutral). Core/A1(7/7)/A2/Pass-2 PRESERVED (new-package, isolated).
      **What Pass-1 PROVED:** status-plumbing (AÇIK≠null barrier, join-status-preservation+promotion, QUARANTINE-leak-proofness, two-role-separation,
      refs-first-class, zone-routing, status-evolution, anti-green). **What it did NOT prove (the Pass-2 burden):** real-source fetch/parse +
      the real-coverage of NVD-join CWE-filling (~61% marginal) + syzbot realization-matching. **NEXT: Pass-2 = real fetchers.**

## Inviolable (for every T)
Do not touch the core (regression 7/7) · Prozessfall DB read-only · epistemic labeling · v0 is NOT CALIBRATED.
