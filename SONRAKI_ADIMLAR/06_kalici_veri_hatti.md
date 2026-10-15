# 06 — Persistent Data Pipeline Decision

**Status:** awaiting decision · **Effort:** engineering round · **Blocker:** none (but a strategic decision)

## What / Why

Right now Tiefenriss uses Prozessfall's SQLite DB as a **read-only proxy** (a hybrid decision,
approved). This is sufficient for the PoC but has two limits:
1. **Timeline is narrow (~6 weeks):** the π axis is cramped, #Ç3 is unreadable (see 05). Time depth
   only comes as data ACCUMULATES.
2. **Static snapshot:** embedding is one-shot (5% DB coverage), the fetch has stopped. Not live.

Decision: **should a persistent data pipeline be built, and how?**

## Options

- **A. Reuse Prozessfall's live fetch:** the NVD/MSRC sidecars already exist
  (Rust daemon + Python sidecar). Have the Tiefenriss adapter periodically read the fresh DB.
  The timeline deepens over time → 05 (#Ç3) and π open up. Plus: it's ready. Minus: a dependency on Prozessfall.
- **B. Have Tiefenriss build its own minimal fetch:** only what Tiefenriss needs (CVE + CPE +
  CWE + embedding, time-stamped). Clean but from scratch.
- **C. Keep the proxy for now:** defer the persistent pipeline until external data (02) and the use-case become clear.

## Side-tasks to be solved on this pipeline

- **Embedding cadence:** embeddings for all CVEs for g_B + regular regen (currently npz cache, temporary).
- **Time-stamped embedding:** unlocks Path B of 05.
- **DB-path portability:** the config-driven path in 07 should become permanent together with this pipeline.
- **params.recompute cadence:** as data grows, the percentile-anchored θ/tier should refresh automatically.

## Inviolable
- The Prozessfall DB stays read-only (writes must go to a separate pipeline/copy, not the live DB).
- As data grows, calibration adjusts automatically via the percentile-anchor — don't leave a frozen number.

## Related files
`prozessfall/` (existing fetch infrastructure), `adapter/params.py` (recompute), `05_C3_erken_uyari_testi.md`.
