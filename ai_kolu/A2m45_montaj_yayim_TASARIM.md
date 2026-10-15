# A2.4 + A2.5 — ATTACK-PATH ASSEMBLY + PUBLICATION TO THE LEDGER — DESIGN

> Phase: the second detail-module of A2 (AI-generator) · Status: DESIGN (NOT code).
> Basis: A2.2+A2.3 (lens+boundary, produces stress-points), A1 (ledger+population+detector). Ordering decision: assembly+
> publication are designed BEFORE the build (otherwise the output of A2.2+A2.3 has nowhere to go = a half-pipe).

## 0. THE CENTRAL PRINCIPLE — GATE the atoms, PRESENT the path (status per-link)
*path* = the operational-deliverable (red-teamer); *prediction* (stress-point / link) = the gate-able-ATOM (reality).
Mixing them is forbidden: if you gate the whole-path then either speculation leaks in (one speculative-link marks the path "confirmed") or
a good-link is lost (one pending-link marks the path "pending"). → **The reality-gate is at the ATOM level; the path is a
PRESENTATION-view** that annotates each ATOM with its own status (type-1 measured / type-2 prediction-pending). İ2's
"status-labeled chain" = status PER-ATOM, gate PER-ATOM. A path does not "realize"; its atoms realize one by one, and
the path's operational-value grows as they are confirmed (no all-or-nothing). **ATOM = node (stress-point) + EDGE (transition);
both are gated, and the path-annotation (weakest-link) COUNTS THE TRANSITIONS TOO** — a path is as strong as its weakest unconfirmed atom.

## 1. A2.4 — attack-path assembly

**What a path is (the 2026-07-18 clarification):** an ATOM-chain — NODE-atoms (stress-point) and EDGE-atoms
(transition) IN SEQUENCE. **BOTH are separately gate-able atoms:**
- **NODE (stress-point):** type-1 (measured-real) or type-2 (prediction). Comes from A2.3.
- **EDGE (transition/pivot):** the AI's exploit-reasoning ("pivot from this UAF to there") = a transition-CLAIM = speculative
  → **a type-2 atom, with its OWN gate, its own falsification-method** (the A2.3 THREE-WAY schema applies to a transition too; otherwise reject).
  Can a transition BECOME type-1? Only with MEASURED exploit-relationship-data (commit-colocation / co-exploitation) — that data does NOT exist in this
  corpus (the deferred T4) → **for now ALL transitions are type-2.**
- **Measured-NEIGHBORHOOD ≠ transition:** a shared-CPE (adapter-graph) SUPPORTS/contextualizes a transition but is not the transition-claim
  ITSELF (neighborhood = a weak-relation; an exploit-transition = a strong-claim). "type-1 backbone" = measured-neighborhood-context,
  not a measured-transition.

**The chaining driver (the researcher's question — neighborhood, value, or provenance?):** the proposal = **exploit-
primitive-composition-reasoning** (the AI reasons about how primitives chain: info-leak→UAF→RIP-control),
BUT each HOP's acceptance-status is separate: type-1 if measured-neighborhood exists, type-2 if a hypothesis (gated). That is, the AI
PROPOSES the chain-reasoning (discovery), while status-labeling + the gate DISCIPLINE it. NEITHER pure-neighborhood (g_A) —
that misses the real exploit-chain; NOR AI-free-association — undisciplined. The middle: primitive-reasoning + a per-hop measurement-status.

**Two directions (İ4):**
- `surface→forward` (discovery): forward projection from a valuable/stress surface — "where does this lead?"
- `target→backward` (operation, TTD-travel): backward from a target — "which path reaches here?" → it exposes
  critical surfaces. **İ3 IS PRESERVED:** a backward-path's contribution to surface-value comes ONLY from type-1 (measured backbone) links;
  type-2 pivots do NOT FEED value until they realize. (The actual feed-wire is in A3; A2.4 only PRODUCES the backward-path,
  it leaves an A3-hook — A2.4 does not build the loop.)

**Energy-governor:** the assembly depth/breadth comes from the core-budget (building a path to a skip-surface).

## 2. A2.5 — publication to the ledger

Each type-2 atom (stress-point + pivot-link) → `dolum.record_prediction`. exposure/horizon/tier_at_creation
are ready in A1; **new fields** (from the A2.3/A2.4 decisions):
- `vuln_class` (CWE-closed-set), `mechanism`, `falsification_method` (=the testable-signal), `measurement_category`
  (1=now / 2=pending-detector), `source_lens` (provenance). A `pred_type` for the stress-point vs pivot-link distinction.
- **A1 schema-extension (small, WITHOUT BREAKING A1):** these fields are added to `ongoru_defteri.Ongoru` (all defaulted →
  old records/tests do not break). test_a1 + regression 7/7 preserved.

**Category routing:**
- cat-1 → a normal pending (the detector tests via tier-crossing).
- cat-2 → **the pending-detector queue = a VIEW ON TOP of the ledger** (`measurement_category==2`), not a separate store
  (single-source-of-truth). Tested once that detector is built. Guard-(c): the cat-2 rate is tracked per-lens.
- cat-3 → not published (rejected in A2.3, to the reject-log).

**single-anchor (decision §3.5):** each prediction is anchored to the SOURCE-surface (for a pivot-link, the source NOT the target) → #Ç4 does not double-count.
**exposure-blind (K1):** A2 produces for EVERY budgeted surface (held-out too); `dolum` assigns exposure blindly; the held-out
veil is in PRESENTATION. Held-out paths are recorded, not shown to the red-teamer.

## 3. The path store (the atom ≠ deliverable distinction)
The ledger = atomic gate-able PREDICTIONS (stress-point + link). **The path = a separate path-registry: a REFERENCE to prediction-ids
+ type-1 measured-links.** This way the reality-gate stays clean on the atoms; the operator gets the path-view
(with each hop's status). Path-realize = "as strong as its weakest unconfirmed-link" (a presentation-annotation, NOT a separate gate).

## 4. DECISIONS (✅ sealed 2026-07-18)
1. **Chaining = exploit-primitive-composition-reasoning (the AI proposes) + per-hop status. TRANSITIONS ARE SEPARATE TYPE-2 ATOMS**
   (their own gate, their own falsification-method): exploit-reasoning=a transition-claim=speculative. Measured-neighborhood supports a transition
   but is not the transition; a transition is type-1 only with a measured-exploit-relationship (colocation, the deferred T4) → for now all are type-2.
2. **The path store = a separate path-registry** (prediction-id referenced); the ledger = atomic gate-able predictions.
3. **Path-realize = a "as strong as the weakest unconfirmed ATOM" presentation-annotation** (NO separate path-gate; node+edge together).
4. **Schema-extension approved:** `vuln_class, mechanism, falsification_method, measurement_category, source_lens,
   pred_type` (node/edge) + a `target-ref` for an edge. All defaulted → A1-compatible, test_a1+regression preserved.
5. **target→backward value-feed = only type-1 atoms (İ3); the actual wire is DEFERRED to A3** (A2.4 leaves a hook, does not build the loop).

## 5. Boundaries (invariant)
The atom-gate / path-presentation distinction · each link status-labeled (a status-less path is forbidden) · feeding only type-1 (İ3) ·
A2 exposure-blind · single-anchor source-surface · do not touch the core · Prozessfall read-only · one-way · output
100% operational. In the A2-BUILD the LLM-operator = the newest Claude (the claude-api reference in that round).
