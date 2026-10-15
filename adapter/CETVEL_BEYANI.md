# v0 RULER DECLARATION — The Tiefenriss Value Ruler

> This document is the **declaration** of the v0 (static value ruler) table in `adapter/ruler.py`.
> v0 IS NOT CALIBRATED — IT IS DECLARED. This document carries that declaration.

## Why it lives under `adapter/` (not in the core)

The core must be **element-agnostic / mission-blind** — that is its identity. If a mission-specific
value-commitment (CWE family X is more valuable than Y) enters the core, that boundary breaks. The mission
enters the system **at the adapter** (v0 = `adapter/ruler.py`). The declaration stands here too → it
reinforces the core's mission-blindness.

## 1. Mission

This ruler is declared for the **LOW-LEVEL OFFENSIVE** mission: the perspective of building a kernel /
memory-level exploitation chain. "Valuable" = that which provides capital/progress toward this chain.

## 2. Status — NOT MEASURED, DECLARED

In spec §7-8, v0 is an **epistemic-infrastructure ruler** — **fixed** like λ, NOT policy-adaptive like θ.
Consequences:

- **It IS NOT calibrated.** The "true value" of a CWE family is not a measurable external fact; in this
  system value is always relational (graph-position g_A). v0 is the **floor/prior-weight** of that relational
  value — the ruler itself. You do not "calibrate" the measuring-rod to reality, you **declare** it;
  everything is measured against it.
- **It cannot be swapped (within-operation).** You can change θ according to the operation; v0 you CANNOT.
  Changing it = retroactively shifting the meaning of all past value-measurements (the same as the λ argument
  of K1: "if something that was 0.9 yesterday becomes 0.4 today, the definition of persistence/value is
  perturbed").
- **KEV/exploit data DOES NOT ENTER here.** Burying "the ones actually exploited" into v0 is circular: it
  tells up front the answer the system is supposed to discover + turns the ruler into an exploit-predictor.
  KEV's place is the VALIDATION layer (see `validate_kev.py`), not a v0-input.

## 3. Priority-ranking + rationale

> **REVIEWER DRAFT — OPEN TO RESEARCHER APPROVAL.** The ranking+values below are a proposal; they can be
> changed by the researcher's operational stance. The numbers are in `ruler.py`; here the **ranking +
> rationale (the value-commitment)** are documented — objections should be made here.

| Tier | CWE families (example) | v0 range | Rationale (low-level offensive) |
|------|----------------------|-----------|-------------------------------|
| **HIGHEST** | UAF (416), double-free (415), OOB-write (787), type-confusion (843), **race/TOCTOU (362)** | 0.80–0.95 | Primitive-spawning memory corruption — the **starting capital** of the exploit-chain, the gateway to a kernel-primitive (write-what-where, RIP control). **race included (2026-07-16):** in this mission race-to-UAF / double-fetch directly spawns memory-corruption; the premier primitive of kernel-LPEs (see §5.2). |
| **HIGH** | info-leak / sensitive-exposure (200), uninitialized (908), OOB-read (125) | 0.70–0.75 | Makes the primitive **usable** — without a KASLR/pointer leak the write-primitive is blind. The leg that weaponizes the chain. |
| **MEDIUM** | privilege-mgmt (269), authz (863/862/284), authn (287/306), locking (667) | 0.55–0.65 | Logic / authority — enters the chain but alone gives no primitive; rises with context. |
| **LOW** | code/cmd-injection (94/78/77) mid-low; web-injection XSS(79)/SQLi(89)/SSRF(918)/path(22)/CSRF(352) | 0.30–0.55 | **Does not enter** the low-level offensive chain. At the bottom of the ruler in this mission. (It may be at the top in another mission — see §4.) |
| **DEFAULT** | a known but tier-less CWE | 0.30 | Neutral-low, flagged (the blind-spot is not hidden). |
| **NO_CWE** | element with no CWE | 0.25 | Neutral, light penalty (blind → cautious), flagged. |

**compound-CWE:** multiple CWEs → **MAX** (the most valuable class dominates; an average would dilute a
critical class). **CVSS is not used** — v0 is a static ruler; severity is already in v0, keep it from
reappearing in π (the K3 reflex).

## 4. Replicability per-mission

This ruler is **specific** to low-level offensive. In the future a SEPARATE ruler can be **declared** for
another mission (e.g. web-app pentest) — this is NOT a "recalibration" of this ruler, but a **second
declaration**. The architecture is ready for it: the `ruler.py` table is mission-labeled (the `MISSION`
constant). RIGHT NOW there is a single ruler: `low-level-offensive`. In a web mission, XSS/SQLi would shift
to the top and memory-corruption to the middle — same core, different ruler. The ruler changes per mission;
**within one mission it is fixed.**

## 5. Deviations / decision-points for the researcher

1. **info-leak tier ADDED (for alignment) → ✅ APPROVED (2026-07-16).** The declaration declares info-leak
   HIGH, but in the current `ruler.py` table the info-leak CWEs (200/908) were MISSING → they got the default
   0.30 = **a conflict with the declaration**. For alignment, CWE-200=0.75, CWE-908=0.70, CWE-125=0.70 were
   added. **The researcher approved — the values accepted as-is.**
2. **race (CWE-362) mismatch → ✅ RESOLVED (2026-07-16): 0.80 KEPT, DECLARATION updated to HIGHEST.** The
   conflict: `ruler.py` 0.80 (HIGHEST) vs the old declaration MEDIUM. Decision (researcher): **race is
   HIGHEST.** Rationale: the declaration's old reading "MEDIUM — gives no primitive alone" is too generic for
   this mission; **in low-level/kernel-exploitation, race-to-UAF and double-fetch directly spawn
   memory-corruption** (most modern kernel-LPEs are races). So the conflict was resolved not by lowering the
   ruler but by **raising the declaration** — the §3 table was updated (race is now on the HIGHEST row). The
   FLAG in the ruler was removed.
