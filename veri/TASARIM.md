# veri/ — Status-Typed Source-Agnostic Data Layer (DESIGN, language-neutral)

> **CODE-LANGUAGE NOTE (2026-07-19):** The code was translated to English (PERMANENT RULE). This design
> document stays Turkish-conceptual. Concept→code mapping: Statu→`Status` (ÖLÇÜLDÜ/TÜRETİLDİ/AÇIK/KARANTİNA→
> MEASURED/DERIVED/OPEN/QUARANTINED) · Öznitelik→`Attribute` · olculmus()→`measured()` · evril()→`evolve()` ·
> BirlesikKayit→`MergedRecord` · KısmiSurface→`PartialSurface` · RealizationOlayi→`RealizationEvent` ·
> SurfaceKaynak/RealizationKaynak→`SurfaceSource`/`RealizationSource` · Zon→`Zone` · birlestir()→`merge()` ·
> topla()→`aggregate()` · arayüz→`is_interface`.

> The RESULT of the T4-research phase: the first real build. NOT "write the adapter" — but "build a
> status-typed source-agnostic data layer". The core is SEALED+element-agnostic (UNTOUCHABLE). This layer is
> ONLY data; a graduated-scope (kernel → +microarch → +crypto → +firmware) adds a new-source at each
> expansion, it does not rewrite the layer.

## Why this layer (the T4 lesson)

The value-architecture was fully-mapped: value is v0-DOMINANT (primitive-intrinsic), g_A is BOUNDED (weak,
scope-did-not-rescue), relation = CHAIN/INTERFACE (not a cluster), realization = syzbot(reachable-quarantine)
+ advisory(chain). The substrate is migrating from generic-NVD (mission-mismatched) to
kernel-CVE-git+syzbot+advisory (mission-fit).

## The central principle — STATUS cannot be separated from the data

The core's §11 status-machine (edge A/B/C = MEASURED/DERIVED/PRODUCED + quarantine) is extended to the
**record-level**. Each field `Attribute` = **value + epistemic-status + provenance + status-HISTORY**.

**`Status` enum (evolvable):**
- `MEASURED`   — read mechanically from the source (no judgment). A trustworthy-value.
- `DERIVED`    — derived via threshold/embedding (visible-policy). A marked-value.
- `OPEN`       — deliberately-empty: "we don't know, we are NOT FORCING it". **OPEN ≠ null.** Downstream must
  not mistake it for measured (otherwise the "leave-it-open" principle collapses). CWE is like this for 39%
  (no-NVD-join, no-derivation).
- `QUARANTINED` — measured BUT suspect (audit-bias / unverifiable). syzbot-realization, colocation,
  microarch-breadth.

**Status is EVOLVABLE (the data-form of the time-gate):** a CWE is OPEN today, becomes MEASURED once the
NVD-backlog fills; a realization is QUARANTINED today, gets promoted once verified. `Attribute.gecmis`
carries every transition (when / which-status / why) — the data-layer counterpart of the type2→type1
promotion (İ5). Time is caller-given (now() is not embedded → deterministic).

**Discipline API (Python has no type-system → an API barrier; in Rust the compiler will enforce it):**
`measured()` returns a value only if MEASURED, otherwise it throws `DisciplineError` → an OPEN/QUARANTINED
value cannot be accidentally used "as-if-measured". (Analogous to the ongoru_defteri.route_to_user barrier.)

## Two-role source (NOT a single-interface)

- **SurfaceSource** → produces a `PartialSurface` (a surface-fragment, status-typed). AI **discovery**
  consumes it.
- **RealizationSource** → produces a `RealizationEvent` (a prediction-confirming EVENT). #Ç4/**the
  time-gate** consumes it.
Separate-roles because their downstream-consumption differs. (kernel-git/NVD/MSRC=surface;
syzbot/advisory=realization.)

## JOIN/enrichment is first-class + status-PRESERVING

A surface does not come from a single source: kernel-git(subsystem+commit) ⋈ NVD(CWE) over `cve_id`. The
sources produce PARTIAL status-typed-records; `merge()` builds the `Surface` while preserving status. On a
field-conflict the **trust-order** is MEASURED > DERIVED > QUARANTINED > OPEN (the measured one FILLS the gap
= an OPEN→MEASURED promotion in the join, written to history). If no-source-provides it → OPEN (not null).

## refs is LOAD-BEARING (this session's blind-spot)

`Surface.refs` is a first-class status-typed field. The one-clean cross-domain-relation =
coordinated-advisory (guest-host chain, dual-ref); value is in the chain/interface. kernel↔kernel could not
be measured because the census was 0/450-refs — the fetcher WILL CAPTURE refs.

## realization-zone-routing (for the AI arm, design-it-now)

`Surface.zon`: `REACHABLE`→machine-#Ç4 (syzbot gives forward-realization) vs `HARDWARE`→human-arm (syzbot
blind).

## domain-profile (small, latent)

The core's policy-parameters (w/α/β/θ) are already domain-tunable. `DomainProfil` = a per-domain weight-set
(kernel→v0-weighted-g_A-bounded). The core READS parameters (untouchable), the adapter GIVES them per-domain.

## Language: Python-stabilize → Rust-incremental

The schema has not yet settled → prototype/stabilize in Python (fast-iteration). Once the schema settles,
port the hot-components (fetch/parse/incremental-daemon) to Rust — the Rust type-system LOCKS the
status-machine AT COMPILE-TIME (the real Rust-value: not performance, but epistemic-discipline-enforcement).
Rust incrementally-per-component.

## Operation: 2-pass

- **Pass-1 (THIS step):** status-typed-schema + STUB-source (architecture-verify, deterministic, no
  LLM/network). Adversarial-stub: OPEN/QUARANTINE/evolution/join-conflict/discipline-barrier are stressed.
  `test_pass1` green, core/A1/A2 regression preserved.
- **Pass-2:** real fetchers (kernel-CVE-git status-typed + syzbot realization). Once the schema settles with
  the stub.

## Modules (English code)

`status.py` (Status/StatusTransition/Attribute/DisciplineError) · `record.py` (PartialSurface/MergedRecord/
SurfaceElement/RealizationEvent/roles/Zone/DomainProfile) · `merge.py` (status-preserving join) ·
`aggregate.py` (subsystem-keyed SurfaceElement + CWE-aggregate) · `stub_source.py` (adversarial Pass-1) ·
`test_pass1.py` (33/33) · `kaynaklar/` (kernel_git/nvd_cwe/syzbot real-sources) · `pass2_kernel.py`
(real-data measurement-runner).
Boundary: THE CORE IS UNTOUCHABLE · status is MECHANICAL (from the source) NO-DERIVATION · no fabrication of
leave-it-OPEN · regression 7/7.
