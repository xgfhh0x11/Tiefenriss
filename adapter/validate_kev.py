"""
validate_kev.py — KEV-AS-VALIDATION HOOK (SKELETON — no data, NOT RUN).

╔══════════════════════════════════════════════════════════════════════════╗
║ PURPOSE: v0/g_A are DECLARED without KEV → system runs → produces high-D   ║
║ surfaces. That output is tested against KEV's HOLD-OUT truth (NEVER seen by║
║ the system): "does the system's attention match the unseen reality?" (§12: ║
║ build, run, read). KEV is validation HERE — NOT a v0-INPUT (circular).     ║
╚══════════════════════════════════════════════════════════════════════════╝

TRAIN/TEST HYGIENE (mandatory):
  • KEV must NOT have ENTERED the v0 ruler OR the g_A weights (hold-out truth).
  • If g_A weights are later calibrated to a target (see the PoC_BULGULAR
    g_A deferral note), that target MUST NOT BE THE SAME AS KEV — otherwise
    calibrate-and-validate-against-the-same-thing = a hidden loop. Calibration target ≠ validation target.

STATUS: SKELETON. KEV data (the CISA Known Exploited Vulnerabilities catalog, cve_id
list) is not here YET. `load_kev()` is filled when data arrives; until then the hook is PASSIVE.
This file IS NOT IMPORTED / CALLED from run_poc — an independent validation tool.

Expected signal (once data arrives): the KEV-hit rate should increase MONOTONICALLY by tier
(stratejik > taktik > atla). If it increases → the system's tension-allocation is aligned with the
exploitation reality it did not see (the framework works). If it does not → either v0/g_A/π
is wrong, or in this domain value is born elsewhere (§12 A/C question). Both are a reading.
"""
from collections import Counter


def load_kev(kev_path: str = None):
    """
    Load the KEV cve_id set. → set[str] or None (if no data).

    SKELETON: the KEV catalog (CISA JSON / cve_id list) is not here yet. When data arrives:
    parse the JSON, return exploited-in-wild cve_ids. For now None → the hook is passive.
    """
    if not kev_path:
        return None
    # TODO(when data arrives): read the CISA KEV JSON → return a {cve_id, ...} set.
    raise NotImplementedError(
        "The KEV loader will be filled when data arrives (CISA KEV JSON). For now call with None.")


def validate(decisions: dict, surfaces: dict, kev_ids: set) -> dict:
    """
    Test the system output (tier/D) against the KEV hold-out.

    decisions: {sid: DepthDecision}, surfaces: {(cwe,vp): Surface}, kev_ids: set[cve_id].
    → KEV-hit rate per tier + lift. (A surface counts as a "hit": ≥1 member in KEV.)

    PASSIVE GUARD: does not run if kev_ids is absent — prevents circularity/empty-run.
    """
    if not kev_ids:
        return {"status": "pasif", "reason": "KEV verisi yok — kanca aktif değil"}

    sid_members = {s.sid: s.members for s in surfaces.values()}
    per_tier_hit = Counter()
    per_tier_tot = Counter()
    for sid, d in decisions.items():
        members = sid_members.get(sid, [])
        hit = any(m in kev_ids for m in members)
        per_tier_tot[d.tier] += 1
        if hit:
            per_tier_hit[d.tier] += 1

    total = sum(per_tier_tot.values())
    total_hit = sum(per_tier_hit.values())
    base_rate = (total_hit / total) if total else 0.0
    rates = {t: (per_tier_hit[t] / per_tier_tot[t]) if per_tier_tot[t] else 0.0
             for t in ("atla", "taktik", "stratejik")}
    # lift: strategic hit-rate vs the base rate — >1 means attention aligned with reality
    lift = (rates["stratejik"] / base_rate) if base_rate else None
    monotone = rates["stratejik"] >= rates["taktik"] >= rates["atla"]

    return {
        "status": "aktif",
        "base_rate": base_rate,
        "tier_kev_hit_rate": rates,
        "stratejik_lift": lift,          # >1 expected (attention ↔ unseen exploitation)
        "monotone_increasing": monotone, # stratejik ≥ taktik ≥ atla?
        "n": total, "n_hit": total_hit,
    }


if __name__ == "__main__":
    print("validate_kev.py — SKELETON. No KEV data → the hook is PASSIVE.")
    print("When data arrives: fill load_kev(path), then:")
    print("  from adapter.run_poc ... build (decisions, surfaces) →")
    print("  validate(decisions, surfaces, load_kev('kev.json'))")
    print("Expected: tier_kev_hit_rate increases monotonically (stratejik>taktik>atla), lift>1.")
