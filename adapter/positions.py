"""
positions.py — graph-POSITION computation: g_A (MEASURED) and g_B (DERIVED).

v2.1 §11 edge-typology + PageRank principle:
  "Do NOT JUDGE quality, COUNT POSITION." A surface's value is not intrinsic but relational —
  how close it is to a valuable/dense neighborhood. PageRank measures exactly this.

g_A — Type A (MEASURED): only shared CPE (vendor:product) edges. CPE-ONLY.
g_B — Type B (DERIVED): embedding cosine ≥ 0.80 edges.

╔══════════════════════════════════════════════════════════════════════════╗
║ CWE-EDGES REMOVED (2026-07-15) — g_A = CPE-ONLY.                          ║
║                                                                            ║
║ Formerly g_A also had shared-CWE edges (W_CWE=1). FINDING: those           ║
║ edges locked g_A onto PURE HUB-POPULARITY —                                ║
║   Spearman(g_A, weighted-degree) = 0.911  (0.9113 on this machine).        ║
║ So g_A measured "how many big CWE-cliques", not "relational position"      ║
║ (huge bug-classes like CWE-79/787/125 connect everyone to everyone →       ║
║ artificially high PageRank; mega-CWEs collapse under degree-correction).   ║
║                                                                            ║
║ Three independent convergences showed the CWE-edge is POLLUTION for this   ║
║ mission: (a) domain-intuition (cross-product same-bug-class ≠ relation),   ║
║ (b) colocation (same-CWE does NOT predict code-colocation), (c) this test. ║
║                                                                            ║
║ DECISION: drop the CWE-edge (NOT degree-normalize — that rescues the dirty ║
║ signal + breeds a near-singleton inflation artefact). g_A CPE-only → hub-  ║
║ popularity-free, still MEASURED. See PoC_BULGULAR.md §"CWE-edge decision".  ║
║ The calibration phase CLOSED here; g_A is "coarse but clean" (W not tuned).║
║                                                                            ║
║ Since W_CPE is the only edge weight, its absolute value does not affect    ║
║ PageRank (column-stochastic normalizes); kept for docs/compatibility.      ║
╚══════════════════════════════════════════════════════════════════════════╝
"""
import numpy as np

W_CPE = 3.0   # shared vendor:product edge (single edge type → absolute value neutral)
SIM_THRESHOLD = 0.80  # v2.1 §11: Type B threshold (fixed in the spec)


def _pagerank(idx_of, edges, n, damping=0.85, iters=100):
    """
    Weighted PageRank (numpy, transparent power-iteration). → normalized to [0,1]
    (divide by max). A position measure; not "popularity" — with dangling correction,
    an iterative equilibrium that distributes share by neighbor-degree.
    """
    if n == 0:
        return {}
    M = np.zeros((n, n), dtype=np.float64)
    for i, j, w in edges:          # undirected: place in both directions
        M[j, i] += w
        M[i, j] += w
    col = M.sum(axis=0)
    dangling = col == 0
    col[dangling] = 1.0
    M = M / col                    # column-stochastic
    r = np.full(n, 1.0 / n)
    teleport = np.full(n, 1.0 / n)
    for _ in range(iters):
        r_new = (1 - damping) * teleport + damping * (M @ r)
        # distribute dangling mass evenly
        r_new += damping * r[dangling].sum() * teleport
        if np.abs(r_new - r).sum() < 1e-12:
            r = r_new
            break
        r = r_new
    mx = r.max()
    r = r / mx if mx > 0 else r
    return r


def compute_g_A(surfaces: dict):
    """
    g_A(surface) over the graph of all CPE-clean surfaces → {sid: g_A ∈ [0,1]}.
    POSITION IS GLOBAL: relative to the whole surface universe. MEASURED (edges from data).

    CPE-ONLY (2026-07-15): only shared vendor:product edges. CWE-edges were
    REMOVED because they locked g_A onto pure hub-popularity (Spearman 0.911) —
    see the module banner + adapter/PoC_BULGULAR.md §"CWE-edge decision".
    """
    sids = list(surfaces.keys())
    idx = {k: i for i, k in enumerate(sids)}
    n = len(sids)

    # edges: only same vendor:product (W_CPE). NO same-CWE edge (pollution).
    by_vp = {}
    for k in sids:
        cwe, vp = k
        by_vp.setdefault(vp, []).append(idx[k])

    edges = []

    def _clique(members, w):
        m = len(members)
        for a in range(m):
            for b in range(a + 1, m):
                edges.append((members[a], members[b], w))

    for members in by_vp.values():
        if len(members) > 1:
            _clique(members, W_CPE)

    r = _pagerank(idx, edges, n)
    return {surfaces[sids[i]].sid: float(r[i]) for i in range(n)}, len(edges)


def compute_g_B(surf_embeddings: dict):
    """
    surf_embeddings: {sid: np.ndarray(384,)} — surface representative embedding
    (the mean of member CVE embeddings). g_B(surface) → {sid: g_B ∈ [0,1]}.

    DERIVED (Type B): cosine ≥ 0.80 edges, then PageRank.
    COVERAGE WARNING: g_B is computed only among surfaces that HAVE an embedding
    → position is relative to this SUBSET, not global. A PoC limit; noted in the report.
    A surface with no embedding → g_B = 0.0 (blind, not hidden).
    """
    sids = list(surf_embeddings.keys())
    n = len(sids)
    if n == 0:
        return {}, 0
    idx = {k: i for i, k in enumerate(sids)}
    E = np.stack([surf_embeddings[k] for k in sids]).astype(np.float64)
    norms = np.linalg.norm(E, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    E = E / norms
    sim = E @ E.T
    edges = []
    for i in range(n):
        for j in range(i + 1, n):
            if sim[i, j] >= SIM_THRESHOLD:
                edges.append((i, j, float(sim[i, j])))  # weight = similarity
    r = _pagerank(idx, edges, n)
    return {sids[i]: float(r[i]) for i in range(n)}, len(edges)
