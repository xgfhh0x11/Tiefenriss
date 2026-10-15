# Tiefenriss — Decision-Intelligence for Low-Level Attack-Surface Exploitability

> An independent research project: a system that estimates *where* memory-corruption vulnerabilities
> are most valuable to an offensive security researcher, and a disciplined, honest methodology for
> testing whether that estimate actually holds against real-world data.
>
> **Author:** independent security researcher, age 18 · **Duration:** several weeks, solo · **Language:** Python
>
> **The most important result of this project is a *negative* one — and reporting it honestly, rather than
> hiding it, is the project's main contribution.**

---

## 1. The problem

Security researchers who work at the low level (kernel, hypervisor, drivers) face a triage problem: tens of
thousands of vulnerabilities exist, but only a fraction lead to *useful exploitation primitives* (use-after-free,
out-of-bounds write, type confusion, race conditions). Which subsystems deserve attention?

Tiefenriss set out to build a "prosthetic eye" for that judgement — not a scanner, but a **decision-intelligence
layer**: given a stream of real vulnerability data, rank the attack surfaces by *exploitability value*.

## 2. The architecture (4 layers)

I deliberately separated concerns so that each layer could be tested — and, crucially, *falsified* —
independently.

```
┌─────────────────────────────────────────────────────────────┐
│  AI-ARM (ai_kolu/)      multi-lens discovery: mechanism-level │
│                         hypotheses, recorded to a prediction  │
│                         notebook with a held-out control group│
├─────────────────────────────────────────────────────────────┤
│  DATA-LAYER (veri/)     status-typed, source-agnostic:        │
│                         every field carries value + epistemic │
│                         status + provenance + history         │
├─────────────────────────────────────────────────────────────┤
│  ADAPTER                maps real signals (CWE value, graph   │
│                         position) onto the core's inputs      │
├─────────────────────────────────────────────────────────────┤
│  SEALED CORE            a fixed mathematical model, untouched  │
│                         once formalized: v = v0·(g_A + w·g_B) │
│                         G = v·(α·π + β·ρ),  D = σ(k·(G − θ))   │
└─────────────────────────────────────────────────────────────┘
```

- **Core** — a sealed scoring model. Element-agnostic: it never knows *what* it is scoring, only a profile
  (intrinsic value `v0`, relational graph-position `g_A/g_B`, signal-persistence `π`, spread `ρ`). It stayed
  untouched through the entire project — every experiment fed it differently, never modified it. (7/7 regression.)
- **Data-layer** — the engineering centrepiece. Every data field is an `Attribute` carrying not just a value but
  an **epistemic status**: `MEASURED` (read from source), `DERIVED` (inferred), `OPEN` (deliberately unknown —
  *not* null), `QUARANTINED` (measured but untrustworthy). A code-level barrier prevents an `OPEN` value from
  being accidentally used as if it were measured. This lets the system be **honest about what it does not know**.
- **AI-arm** — a multi-lens operator that produces falsifiable, mechanism-level predictions ("session-teardown
  race → use-after-free in the SMB server"), each recorded with a bounded falsification horizon.

## 3. The method — falsify your own design

The project's real discipline was a rule I imposed on myself: **every load-bearing assumption must be tested
against real data with a pre-registered expectation, and a negative result must be accepted, not rationalized.**

Data: ~8,000 real Linux kernel CVEs (2019–2026) from the Linux CNA, joined with NVD (CWE), syzbot (fuzzing
realization), and later ~3,200 Windows CVEs from Microsoft's MSRC feed (which uniquely publishes an expert
**Exploitability Index**).

### Finding 1 — "graph relatedness intelligence" does not exist (three independent strikes)

The model assumed a subsystem's value is partly *relational* (`g_A`): important subsystems sit near other
important ones in a graph. I tested three different ways to build that graph:

| Graph edge | Result | Verdict |
|---|---|---|
| Shared-CWE edges | Spearman **0.91** with raw node degree | It was measuring *hub popularity*, not relatedness |
| File co-occurrence (T4) | dead — too sparse | no signal |
| Semantic bug-profile embeddings | Spearman **0.85** with activity; forward-validity **−0.10** | re-encoding *size*, not value |

I ran a **controlled external-validity test**: does a high-`g_A` subsystem actually produce more realized
exploitation later, *controlling for reachability and intrinsic value*? Partial correlation ≈ **0**, robust across
six configurations. **Conclusion: graph relatedness contributes nothing independent. I removed `g_A` from the
model entirely** — proven hollow, not assumed. Value is *intrinsic*, not relational.

### Finding 2 — a temporal backtest (validate today, without waiting)

Since forward-validation is time-gated (you must wait for future CVEs), I built a **backtest harness**: freeze the
model as-of 2023, predict, then compare against what *actually* happened in 2024–2026 (data already in hand).

- The intrinsic-value signal `v0` showed **partial-Spearman +0.333** (p < 0.0001) for predicting future
  *value-character* above a trivial activity baseline. Encouraging — the model captured *something* persistent.

### Finding 3 — the decisive negative: value is externally unanchored

The value model's heart is `v0`, a **declared** ruler of CWE-family exploitation value (deliberately not
calibrated, to avoid circularity). I had never been able to externally validate it — until Windows/MSRC gave a
real, expert exploitability ground-truth. So I asked directly: **does `v0` correlate with real-world
exploitability?**

| Signal | Domain | Correlation with `v0` |
|---|---|---|
| MSRC Exploitability Index | Windows | **−0.047** (n=2,164) |
| EPSS exploitation-probability | Linux | **+0.023** (n=7,671) |
| CISA KEV (known-exploited) | Linux | N=7 — insufficient |

Two domains, three independent signals, all ≈ **0**. And the 2023→2024-26 value-model did **not** generalize to
Windows (+0.039 vs Linux's +0.333). **The value model — the core of the whole system — is not externally
anchored to any generic exploitation signal.**

## 4. What this means (the honest conclusion)

Tiefenriss did **not** produce a validated general predictor of exploitation. The central hypothesis — that
CWE-family value density measures broadly-meaningful exploitability — was **not supported** by external data.

There is a genuine, unresolved tension here, and I state it rather than paper over it: my design intent was that
value is *perspective-relative* (an exploit-developer's notion of a "good primitive" ≠ a generic attacker's
likelihood of mass-exploitation). The null results are *consistent* with that intent — the two constructs
genuinely differ. But that same intent makes `v0` **unfalsifiable by generic data**, which collides with the
project's own external-validation ethos. Resolving whether the "eye" is a real predictor or a
perspective-relative heuristic is the open question the project ends on — honestly unresolved.

## 5. What actually worked, and what I learned

**Engineering that stands:**
- A clean, tested, status-typed data layer over 8,000+ real CVEs (35/35 tests, sealed core never modified).
- A reusable **backtest harness** that settles a hypothesis in minutes instead of months.
- A source-agnostic architecture that absorbed a completely different second domain (Windows/MSRC) by adding
  *one* module — no rewrite. The staged-scope design held.

**The skill this project demonstrates is not "I shipped a product." It is:**
- Designing a multi-layer system with clean, independently-testable seams.
- Building an **epistemic discipline into the code itself** (measured vs. open vs. quarantined; a held-out
  control group set up on day one to detect self-fulfilling bias).
- Forming quantitative hypotheses, pre-registering expectations, running controlled/partial-correlation tests,
  and **accepting negative results** — including killing my own most-cherished idea (`g_A`) three times over.

I set out to build an eye that would not lie to itself. Over several weeks that eye was turned on the project's
own assumptions, and it reported — clearly and against my hopes — that the central one did not hold. That
outcome feels like a loss. But the machine did exactly what it was designed to do, and I learned to trust a
negative result more than a convenient one. For a research engineer, that is the point.

---

## Repository map

| Path | What it is |
|---|---|
| `Tiefenriss/` | the sealed mathematical core (`core.py`, `model.py`) + its formalization |
| `veri/` | status-typed source-agnostic data layer (`status.py`, `merge.py`, `aggregate.py`, `wire_core.py`) |
| `veri/backtest.py`, `backtest_gb.py`, `windows_harness.py` | the validation harness (the heart of the method) |
| `ai_kolu/` | the multi-lens AI operator + falsifiable prediction notebook (held-out control) |
| `adapter/` | signal → core mapping (the declared v0 ruler, graph positions) |

*Running the tests: from the repo root, `python3 -m veri.test_pass1`, `python3 -m cekirdek.test_kadran`,
`python3 -m veri.backtest`. Design notes are kept in Turkish (the author's thinking language); all code and
identifiers are in English.*
