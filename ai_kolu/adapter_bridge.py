"""
adapter_bridge.py — ai_kolu → adapter bridge: surface → kernel-tier map.

One-way dependency (ai_kolu → adapter → cekirdek; never the reverse). Prozessfall READ-ONLY.
Both dolum's `tier_at_creation` snapshot and the detector's `current_tier` are fed from this —
both use the kernel's OWN tier-decision (the verdict comes from the kernel).
"""
from adapter.surfaces import load_surfaces, DB_DEFAULT
from adapter.positions import compute_g_A, compute_g_B
from adapter.embeddings import surface_embeddings
from adapter.build import build_profiles
from adapter.core_bridge import evaluate
from adapter import params as tief_params
from adapter.run_poc import select_subset


def surface_tiers(db: str | None = None, emb_cache: str | None = None,
                  gb_scope: str = "global", cap: int = 250, min_days: int = 2) -> dict:
    """
    Runs the adapter pipeline and returns {surface_id: tier} (the evaluated subset — same as run_poc).
    Heavy (embedding); sped up with emb_cache. Read-only (embedding to the npz cache, NOT the DB).
    """
    db = db or DB_DEFAULT
    all_surf, cwe_fp = load_surfaces(db)
    subset = select_subset(all_surf, min_days=min_days, cap=cap)
    g_A, _ = compute_g_A(all_surf)
    gb_pop = all_surf if gb_scope == "global" else subset
    emb = surface_embeddings(gb_pop, db, regenerate=True, cache_path=emb_cache)
    g_B, _ = compute_g_B(emb)
    profiles, now = build_profiles(subset, g_A, g_B, cwe_fp)
    p = tief_params.DEFAULT
    return {sid: evaluate(prof, now, p).tier for sid, (prof, _) in profiles.items()}
