"""
embeddings.py — embedding provisioning for g_B (the Prozessfall DB stays READ-ONLY).

The existing cve_embeddings (5% coverage) does not cover most PoC members → we regenerate
the missing ones IN MEMORY (all-MiniLM-L6-v2, the same model as semantic_corellation.py).
WE DO NOT WRITE TO THE DB — Prozessfall is a read-only data lake (researcher's decision).

surface representative embedding = the MEAN of member CVE embeddings (CHOSEN: equal
weight; an alternative CVSS-weighted mean is possible, but it was kept equal so as not to
leak v0/π in here).
"""
import os
import json
import sqlite3
import numpy as np

MODEL_NAME = "all-MiniLM-L6-v2"
_model = None


def _get_model():
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer
        _model = SentenceTransformer(MODEL_NAME)
    return _model


def _extract_core(desc: str) -> str:
    """The same simplification as semantic_corellation.extract_core (consistency)."""
    out = []
    for line in (desc or "").strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("In the Linux kernel") or \
           line.startswith("This is the same bug"):
            continue
        out.append(line)
    return " ".join(out[:10])


def _load_cache(cache_path):
    """npz cache → {cve_id: vec}. Empty if none. (Separate from the DB; the DB stays read-only.)"""
    if not cache_path or not os.path.exists(cache_path):
        return {}
    z = np.load(cache_path, allow_pickle=False)
    return {cid: z[cid] for cid in z.files}


def _save_cache(cache_path, store):
    if cache_path:
        np.savez(cache_path, **store)


def embeddings_for(cve_ids: set[str], db_path: str,
                   regenerate: bool = True, cache_path: str = None) -> dict[str, np.ndarray]:
    """{cve_id: vec(384,)}. Order: npz cache → DB → (regenerate) build in memory + write to cache.
    regenerate=False → only the existing ones (fast; for g_A-dominant work). NEVER written to the DB."""
    have = dict(_load_cache(cache_path))
    have = {c: have[c] for c in have if c in cve_ids}  # only the requested ones
    n_from_cache = len(have)

    conn = sqlite3.connect(db_path)
    need_db = [c for c in cve_ids if c not in have]
    for chunk in _chunks(need_db, 900):   # SQLite IN() 999-variable limit
        q = "SELECT cve_id, embedding FROM cve_embeddings WHERE cve_id IN ({})".format(
            ",".join("?" * len(chunk)))
        for cid, blob in conn.execute(q, tuple(chunk)):
            have[cid] = np.frombuffer(blob, dtype=np.float32).copy()

    missing = [c for c in cve_ids if c not in have] if regenerate else []
    if missing:
        texts = {}
        for chunk in _chunks(missing, 900):
            q = "SELECT cve_id, description FROM cve_raw WHERE cve_id IN ({})".format(
                ",".join("?" * len(chunk)))
            for cid, desc in conn.execute(q, tuple(chunk)):
                core = _extract_core(desc)
                if core:
                    texts[cid] = core
        ids = list(texts)
        if ids:
            vecs = _get_model().encode([texts[c] for c in ids],
                                       batch_size=64, show_progress_bar=False)
            for c, v in zip(ids, np.asarray(vecs, dtype=np.float32)):
                have[c] = v
    conn.close()

    # update the cache (including newly generated ones) — to npz, not to the DB
    if cache_path and len(have) > n_from_cache:
        merged = dict(_load_cache(cache_path))
        merged.update(have)
        _save_cache(cache_path, merged)
    return have


def _chunks(seq, n):
    seq = list(seq)
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def surface_embeddings(surfaces: dict, db_path: str,
                       regenerate: bool = True, cache_path: str = None) -> dict[str, np.ndarray]:
    """{sid: mean(member embedding)}. Surfaces with no embedding at all are skipped."""
    all_ids = set()
    for s in surfaces.values():
        all_ids.update(s.members)
    cve_vec = embeddings_for(all_ids, db_path, regenerate=regenerate, cache_path=cache_path)
    out = {}
    for s in surfaces.values():
        vs = [cve_vec[c] for c in s.members if c in cve_vec]
        if vs:
            out[s.sid] = np.mean(np.stack(vs), axis=0)
    return out
