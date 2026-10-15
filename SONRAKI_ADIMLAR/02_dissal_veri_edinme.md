# 02 — External Ground-Truth Data Acquisition (ENABLER)

**Status:** open · **Effort:** medium (data source + integration) · **Blocker:** none
**Why it's a priority:** both 03 (g_A calibration) and 04 (KEV validation) depend on it. Highest leverage.

## What / Why

The one thing the system currently lacks: **an external truth the system has not seen.** The
existing corpus (cve_raw + embeddings + msrc) is all "the system's own input" — there is internal
consistency but no external ground-truth. This is why #Ç3 of the three measurements was deferred,
and why g_A calibration is blocked.

Three candidate data sources (each unlocks different tasks):

| Data | What it provides | What it unlocks |
|------|----------|-----------|
| **CISA KEV** (Known Exploited Vulns) | list of genuinely-exploited cve_id | 04 (KEV validation), weak g_A signal |
| **Exploit-chain / PoC corpus** | which CVEs are exploited together | 03 (g_A: relatedness ground-truth) |
| **Commit-colocation** | CVEs fixed in the same commit/patch | 03 (g_A: structural-proximity ground-truth) |

## How to start

1. **KEV (easiest):** the CISA KEV catalog is public JSON (`known_exploited_vulnerabilities.json`).
   Download it, extract the `cve_id` set. The `adapter/validate_kev.py::load_kev()` skeleton is
   ready — fill it in.
2. **Commit-colocation (strong for the kernel):** "Fixes:" trailers from the Linux kernel git log,
   or multiple CVE references in the same commit → pairs of co-fixed CVEs. This gives an EXTERNAL
   target for g_A's question of "is CPE-adjacency or CWE-adjacency better."
3. **Exploit-chain:** CVEs used together, from exploit-db / public PoCs (more laborious, noisy).
   Last resort.

## Inviolable — TRAIN/TEST HYGIENE (critical)

- This data **DOES NOT ENTER v0** (circular — see CETVEL_BEYANI §2). It only becomes a
  calibration-target (03) or a validation-target (04).
- **Calibration target ≠ validation target.** If you calibrate g_A to commit-colocation, validate
  the system against KEV (a different target). Calibrating and validating on the same data = a
  hidden loop.
- The data must be a "system-unseen" hold-out — it must not leak into v0/g_A production.

## Related files
`adapter/validate_kev.py` (KEV-loader skeleton), `03_gA_agirlik_kalibrasyonu.md`,
`04_kev_validation_aktivasyon.md`.
