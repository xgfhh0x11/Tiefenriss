# 00 — START HERE (Rome / new-machine resume guide)

> This folder (`SONRAKI_ADIMLAR/`) keeps the upcoming tasks, each as a separate .md file.
> To pick up where you left off on a new machine, read THIS file FIRST.

## What is Tiefenriss (1 minute)

Offensive attack-surface + exploitability decision-intelligence — "a small Palantir, for the
attacking side." An **attention engine** that decides, among thousands of vulnerabilities, which
one to "look at, and how deeply." 4 layers: CORE (exists, sealed) → ADAPTER (exists) → DATA
(Prozessfall proxy) → AI ARM (future).

**WARNING — do not conflate three separate efforts:** this repo holds together `Tiefenriss/`
(ACTIVE), `prozessfall/` (data infrastructure, not part of Tiefenriss but its data pipeline), and
`Tiefenriss/exploitation_machine_HANDOFF.md` (a separate theoretical effort, on the back burner).
Details: `memory/tiefenriss-project-identity.md`.

## Canonical records (reading order)

1. `Tiefenriss/cekirdek_formalizasyon_v2_1.md` — the core's sealed mathematics
2. `cekirdek/INSA_GUNLUGU.md` — core build log + open measurements
3. `adapter/PoC_BULGULAR.md` — ALL adapter findings/decisions/deviations (most current state)
4. `adapter/CETVEL_BEYANI.md` — the v0 value-ruler declaration
5. `memory_snapshot/*.md` — project identity + adapter-state summary (Claude memory snapshot)

## How to run (from the project root)

```bash
cd <repo>/Tiefenriss        # proje kökü — kök sys.path'te, cekirdek+adapter kardeş paket
python3 -m cekirdek.test_kadran         # REGRESSION — 7/7 geçmeli (her değişiklikten sonra çalıştır)
python3 -m adapter.run_poc --gb-scope global --emb-cache /tmp/emb_cache.npz   # uçtan uca PoC
python3 -m adapter.calibrate            # θ/k kalibrasyon taraması
python3 -m adapter.compare_subsystem --emb-cache /tmp/emb_cache.npz   # CPE vs keyword
```

**Dependencies:** Python 3.10+, `numpy`, `sentence-transformers`, `tomli` (for below 3.11).
**emb_cache:** absent on a new machine → the first `--gb-scope global` run produces ~3670
embeddings (~1-2 min, downloads `all-MiniLM-L6-v2`), then writes to the cache → subsequent runs
take 1.4s.

## ⚠️ PORTABILITY GOTCHA — THE FIRST THING THAT WILL BREAK ON ROME

The `DB_DEFAULT` in `adapter/surfaces.py` is an **absolute path**:
`/home/tylersec/Tiefenriss/prozessfall/prokaryotes/prozessfall.db`.
On a new machine where the repo lives at a different path (or Windows/WSL) THIS WILL BREAK. See
`07_kucuk_isler.md` — the first task is to make this relative/config-driven. Temporary workaround:
update DB_DEFAULT by hand. (The DB file ships inside the repo:
`prozessfall/prokaryotes/prozessfall.db`, ~9.9 MB.)

## Inviolable boundaries (apply to every task)

- **DO NOT TOUCH the core** (`cekirdek/model.py`, `core.py`). Regression must stay 7/7.
- **Prozessfall DB is READ-ONLY** — never write (embeddings go to the npz cache, not the DB).
- **Epistemic labeling:** every value should stay marked as `ÖLÇÜLDÜ` (Type A) / `TÜRETİLDİ`
  (Type B, threshold) / `SEÇİLDİ` (design) / `İLAN EDİLDİ` (infrastructure-ruler).
- **v0 is NOT CALIBRATED, it is DECLARED.** KEV/exploit data is NOT a v0 input, it is validation.
- **One-directional dependency:** adapter → core, never the reverse.
- **BE SUSPICIOUS of a "too good" result** — control group / artifact test (2 traps were caught
  this round).

## Open tasks (the files in this folder)

| # | Task | Status | Blocker |
|---|-----|-------|--------|
| 01 | v0 declaration approval | awaiting decision | researcher (quick) |
| 02 | External ground-truth data acquisition (KEV/exploit-chain/commit-colocation) | ENABLER | data source |
| 03 | ~~g_A weight calibration~~ → **CWE-edge removed, g_A=CPE-only** | **CLOSED (2026-07-15)** | — |
| 04 | KEV-validation activation | skeleton ready | depends on 02 (KEV) |
| 05 | #Ç3 early-warning test | deferred | multi-year history / time-stamped embedding |
| 06 | Persistent data pipeline | awaiting decision | engineering round |
| 07 | Small tasks (DB-path portability, v>1, keyword→score promotion) | open | — |

**Dependency chain:** 02 (data acquisition) → ~~03 (g_A calibrate)~~ + 04 (KEV validate). 05 and 06 are independent.

> **UPDATE (2026-07-15) — THE CALIBRATION PHASE IS CLOSED.** 03 is no longer weight-calibration:
> g_A was locked to hub popularity (Spearman=0.911, confirmed 0.9113 on this machine) → CWE-edges
> were REMOVED, **g_A = CPE-only** (foundational cleanup, not calibration). Details:
> `adapter/PoC_BULGULAR.md` §"CWE-kenar kararı". kernel-lump/subsystem-granularity/W-tuning were
> **deliberately left** (never-ending calibration). g_A is now "coarse but clean" → sufficient.
> **Next phase: AI ARM ARCHITECTURE** (not code, design first). 02/04 (external data +
> KEV-validation) are still open but no longer for g_A-calibration — for Phase-B (product)
> validation.
