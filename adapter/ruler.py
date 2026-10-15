"""
ruler.py — v0 STATIC VALUE RULER (CWE → [0,1]).

v2.1 §7: v0 is epistemic-INFRASTRUCTURE. "Intrinsic value base" — CWE weight etc. FROZEN.
The ruler does not move; moving it shifts the reality the system sees (same status as λ).

╔══════════════════════════════════════════════════════════════════════════╗
║ EPISTEMIC STATUS: DECLARED (infra-ruler) — NOT MEASURED, NOT CALIBRATED.   ║
║ This is an infrastructure-ruler (CONSTANT like λ), NOT adaptive like θ.    ║
║ Not calibrated → DECLARED. A CWE family's "true value" is not a measurable ║
║ external fact; value is relational in this system (g_A). v0 is the BASE of ║
║ that value = the ruler itself. Declare the meter stick, don't calibrate it.║
║ NOT SWAPPABLE (in-operation): changing it retroactively invalidates past   ║
║ value-measurements (K1's λ argument). KEV/exploit data DOES NOT ENTER here ║
║ (circular) — it goes to the validation layer (validate_kev.py).            ║
║ FULL DECLARATION + rationale + deviations: adapter/CETVEL_BEYANI.md        ║
╚══════════════════════════════════════════════════════════════════════════╝

DESIGN RULES:
  • FAMILY level, not individual CWE. Giving individual weights to 384 distinct CWEs
    would smuggle judgment into the system. A small, defensible tier table.
  • CVSS IS NOT USED. CVSS is per-instance severity + partly judgment; v0 must be a
    static ruler. Severity is already in v0 (the ruler), again in π, keep them unmixed (K3 reflex).
  • compound-CWE (>1) → MAX (the most valuable class dominates). Averaging would dilute
    a critical class.
  • Unknown/no-CWE → neutral default (flagged). The blind spot is not hidden.
"""

# Which mission this ruler was DECLARED for. The ruler changes per mission; WITHIN a mission
# it is fixed. Another mission (e.g. web-pentest) needs a SEPARATE declaration — not a calibration of this ruler.
MISSION = "low-level-offensive"

# CWE family → v0 base value. DECLARED (see CETVEL_BEYANI.md).
# Tier structure aligned with the declaration: HIGHEST > HIGH > MEDIUM > LOW.
_TIER = {
    # === HIGHEST — primitive-spawning memory corruption (chain starting capital) ===
    "CWE-416": 0.95,  # UAF
    "CWE-415": 0.90,  # double-free
    "CWE-787": 0.90,  # OOB write
    "CWE-843": 0.80,  # type confusion
    "CWE-119": 0.80,  # buffer bounds (general)
    "CWE-362": 0.80,  # race / TOCTOU — race-to-UAF, double-fetch → direct memory-corruption;
                      #                 premier primitive in kernel-exploitation (declaration HIGHEST, 2026-07-16 decision)
    # === HIGH — makes the primitive usable (info-leak: KASLR/pointer) ===
    # [declaration-alignment, ADDED] previously absent → it took default 0.30 = conflict with the declaration.
    "CWE-200": 0.75,  # sensitive info exposure (info-leak)
    "CWE-908": 0.70,  # use of uninitialized resource (leak source)
    "CWE-125": 0.70,  # OOB read (as a leak primitive)
    # === MEDIUM — logic / authority (enters the chain, gives no primitive alone) ===
    # (race/TOCTOU 362 → moved to HIGHEST, 2026-07-16 decision; see declaration §3/§5)
    "CWE-190": 0.70,  # integer overflow (a bridge to most memory-corruption)
    "CWE-863": 0.65, "CWE-862": 0.60, "CWE-284": 0.60,  # authz
    "CWE-269": 0.60,                                     # privilege mgmt
    "CWE-667": 0.60,  # locking
    "CWE-287": 0.60, "CWE-306": 0.55,                    # authn
    "CWE-476": 0.55,  # NULL deref (mostly DoS)
    # === LOW — not part of the low-level offensive chain (at the bottom in this mission) ===
    "CWE-94": 0.55, "CWE-78": 0.55, "CWE-77": 0.50,      # code/cmd injection (mid-low)
    "CWE-404": 0.45,  # improper resource shutdown
    "CWE-401": 0.45,  # memory leak (resource leak, not information)
    "CWE-918": 0.45, "CWE-74": 0.40,                     # ssrf / injection
    "CWE-89": 0.40, "CWE-22": 0.40,                      # sqli / path
    "CWE-20": 0.35, "CWE-798": 0.35,                     # input-validation / hardcoded creds
    "CWE-79": 0.30, "CWE-352": 0.30, "CWE-259": 0.30,    # xss / csrf / hardcoded pw
}

_DEFAULT = 0.30          # a known CWE not in the tier → neutral-low (CHOSEN)
_NO_CWE_DEFAULT = 0.25   # element with no CWE → neutral, light penalty (blind → cautious). flagged.


def v0_for(cwe_ids: list[str]) -> tuple[float, str]:
    """
    Produce a static v0 base from a CWE list. → (v0, status_label).

    status_label for tracking/reporting: 'tier' | 'default' | 'no_cwe'.
    The core does not see this; the adapter keeps it for transparency.
    """
    if not cwe_ids:
        return _NO_CWE_DEFAULT, "no_cwe"
    vals = [_TIER.get(c, _DEFAULT) for c in cwe_ids]
    status = "tier" if any(c in _TIER for c in cwe_ids) else "default"
    return max(vals), status  # compound → MAX (CHOSEN)
