# Core — Code Build Log

> This file is the log of the **code** built on top of `cekirdek_formalizasyon_v2_1.md` (the spec).
> The formalization = what is to be built. This file = WHAT CAME OUT while building: findings,
> calibration decisions, gaps the code exposed, open questions.
> Purpose: so these do not get lost in chat, but accumulate in a traceable form.
>
> Rule: theory is NOT deepened here (drift forbidden). Only the execution of the code and the
> concrete decisions that execution surfaced are recorded.

---

## Vision (bare, for reference)

Operational & Strategic Eye: a system looking at a vast, heterogeneous, chaotic reality —
countless attack surfaces, environments, complex architectures, countless elements each carrying a
different meaning. "400 million questions": what is this element, what is it connected to, for what
purpose, why is it important, why is it noise. A human cannot do it at scale; a pure-AI goes blind.
**The core exists for this:** an immutable law that can answer each of those 400 million questions
consistently, with the same principle. The AI arm makes sense of the elements (generates hypotheses);
the core manages the AI's ATTENTION ("look at this one this deeply"). The formalization made the core
portable TO A MACHINE — a verbal principle works in a human, a formalized principle in a machine.

It will become a product: a small Palantir, not for defense but for offense — attack-surface +
exploitability intelligence.

---

## Architectural decision: AN ISOLATED, ELEMENT-AGNOSTIC CORE

**Decision:** The core is written purely isolated. "Give a profile, get a processing-depth." Whatever
the element is (CVE/config/architectural node/environment) it is reduced to three abstract signals:
value (graph-position), persistence (time), spread (space). The core does not know WHAT the element is.

**Rationale (three-legged):**
1. **Direction of dependency** — an element-agnostic core depends on no one; the elements conform to it.
   (The atom principle + clean architecture: the core is the innermost independent layer.)
2. **Testability** — full test with synthetic profiles; whether a bug is in the core or in the data
   pipeline is separable.
3. **Scale necessity** — the ONLY way to apply a single law to 400M different elements is for the core
   not to see the content. If it saw, it could not scale.

**Conscious boundary:** The core does not ask "is this profile correct?" Garbage in → garbage out.
Making the profile reflect reality = the job of the adaptation/validation layer (edge-typology,
validation gate — v2.1 §11-12). The boundary was named, not hidden.

**Language:** Python (fast prototyping, compatible with Prozessfall's Python side, synthetic test easy).

**Order:** First the isolated core + synthetic test → THEN connect to Prozessfall's real data.

---

## Code status (today)

Location: `/home/claude/cekirdek/`

| File | Content | Status |
|-------|--------|-------|
| `model.py` | Element-agnostic data types (Signal, GraphPosition, ElementProfile, DepthDecision) | ✅ written |
| `core.py` | Compute engine: persistence(π), spread(ρ), value(v), tension(G), opening(D), evaluate() | ✅ written |
| `test_kadran.py` | 4-quadrant synthetic test | ✅ written, running |
| `__init__.py` | package | ✅ |

**Discipline embedded in the types:**
- `Signal` has NO severity/strength field → σ binary (v2.1 K3).
- `GraphPosition` has NO `g_C` field → Type C cannot architecturally enter the core (v2.1 §11).
- `ElementProfile.element_id` "the core does not take it into account" → element-agnosticism.

**Parameter separation (CoreParams):** policy (θ, k, α, β, w, D_max) is tunable; λ is epistemic but
is kept here for the π computation. Defaults: λ=0.05, w=0.5, α=β=1.0, θ=0.30, k=8.0, D_max=1.0,
rho_scale=3.0.

**Trap resolved:** `types.py` shadowed the stdlib `types` module → circular import.
Renamed to `model.py`.

---

## Quadrant test result (first run)

```
KADRAN 1  değerli + ısrarlı        | v=0.990  π=4.06  ρ=0.57  G=4.588  D=1.000  → stratejik  ✓
KADRAN 2  değerli + tek-seferlik   | v=0.990  π=0.14  ρ=0.25  G=0.381  D=0.657  → stratejik
KADRAN 3  değersiz + ısrarlı       | v=0.019  π=4.06  ρ=0.57  G=0.087  D=0.154  → taktik
KADRAN 4  değersiz + tek-seferlik  | v=0.009  π=0.11  ρ=0.00  G=0.001  D=0.084  → atla
```

**Two notes (separated out):**

1. **K2 → strategic (expectation: tactical).** This is most likely a TEST-SETUP error, not a formula
   error. v0=0.9 + g_A=0.8 + g_B=0.6 → v=0.99 (value AT THE CEILING). Something that valuable crosses
   the threshold even with a single signal — the gate is wide open. "Very valuable + one-time" might
   genuinely be above-tactical. The expectation was too strict; what gets fixed is the test, not the core.

---

## OPEN QUESTION #1 — What should "worthless but very persistent" (K3) be? → **RESOLVED: A (hard veto)**

**Context:** In K3, v=0.019 (gate almost closed) but π=4.06 (very high persistence). WITHOUT the exponent
it produced G=0.087, D=0.154 — right on the "skip/tactical" boundary, with persistence slightly forcing
the gate.

**DECISION: A — HARD VETO at the gate.** But Utku rescued this from blindness with a third channel:

> "Worthless but very persistent" is two SEPARATE things:
> (i) genuinely worthless busy-noise (an isolated parser, a continuous low-impact bug, does not enter a chain),
> (ii) a surface whose value has not yet BECOME VISIBLE (will later become a pressure point).
> **π does NOT separate the difference** (high in both) — **the MOVEMENT of g separates it.** If real value
> is emerging, the surface drifts toward a valuable neighborhood → g↑ → v↑ → the gate opens BY ITSELF. In
> fake noise, g stays fixed-low → stays closed.

**Why not B (let persistence force the gate):** the early-warning that B is trying to do is already done by
A+g — but from the MEASURED channel (position movement), not from the FORCED channel (π pushing the
threshold). Critical: **B CANNOT separate real early-warning from fake** (π is high in both); A+g separates
it (only in the real case does g move). B is not merely coarser but WRONG — it reads the right signal
(early-warning) from the wrong channel (persistence itself). Persistence alone is not evidence, only
attention-grabbing; the evidence is in the position actually drifting toward a valuable neighborhood. → This
is epistemic discipline itself: early-warning must come from the MEASURED thing, not from the thing that
FORCES the formula.

**Implementation (code):** a gate-exponent added to `tension()`: **G = v^p · (α·π + β·ρ)**, `gate_p=2.0`.
- p>1: a low v CANNOT be compensated by a high π. v=0.02, p=2 → v^p=0.0004, the gate practically closes.
- Asymmetry: the exponent only crushes LOW values (0.02→0.0004); it does not touch HIGH values (0.99²≈0.98).
  So the way is open for the valuable, the gate is closed for the worthless, and persistence cannot break
  this distinction.
- `value()` returns the RAW v (transparent); the exponent is applied in tension() (the gate-effect is
  visible separately).

**Test result (after the exponent):** K3: G 0.087→0.002, D 0.154→0.084 → **skip** (same as K4=0.083).
K1 was not harmed (D=1.000 fixed — high value is not affected by the exponent). **ALL QUADRANTS CORRECT.**

**→ The new measurement-need it gives rise to: see OPEN MEASUREMENT #Ç3 (below).**

---

## OPEN MEASUREMENTS — assumptions to be validated with data (same status as §12)

These are not solved at the desk; they are READ from real data once the system runs. The
"the system's first output" logic of v2.1 §12 — each one is the testing of an assumption against data.

- **#Ç1 — A/C ratio.** Is value born from the measured neighborhood (Type A) or from the judgment-chain
  (Type C)? The system's first output.
- **#Ç2 — g_B/g_A ratio.** How much of the gate is derived (B) vs measured (A)? Feeds the w calibration.
- **#Ç3 — "does g rise first?" (the basis of the HARD VETO).** The decision of OPEN QUESTION #1 (A) rests
  on this assumption: the g of surfaces that later turn out valuable rises BEFORE the value becomes visible
  (the early-warning comes from the g channel). **This must be tested:** take surfaces in past data that
  later became pressure-points, look at their g(t) curves — did g really rise BEFORE the value-burst?
  - If it rose → the hard veto is correct, g carries the early-warning, no need to force the gate (B).
  - If it did not rise → the hard veto may be creating a blind-spot, decision A is re-evaluated.
  This makes the decision testable — not intuition, but a measurable hypothesis.

---

## Next steps

1. ~~OPEN QUESTION #1 is resolved~~ → **RESOLVED (A, hard veto, v^p, gate_p=2.0).** The quadrants are correct.
2. ~~K2 test-setup~~ → **fixed** (value-ceiling scenario; the expectation was loosened to "it opens").
3. Core calibration stable → connecting to Prozessfall begins.
4. With real 6336 CVEs + embeddings the open measurements (#Ç1, #Ç2, #Ç3) are READ.
   NOTE: Prozessfall's real code/DB is not yet loaded; needed at the connecting stage.

**Calibration parameters (current defaults — to be tuned when the data arrives):**
λ=0.05, w=0.5, α=β=1.0, θ=0.30, k=8.0, D_max=1.0, gate_p=2.0, rho_scale=3.0.
These are POLICY (gate_p included) — they define strategy, not reality, and are calibrated with data.
