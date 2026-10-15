"""
realization_test.py — g_A EXTERNAL-VALIDITY test (CONTROLLED). Does g_A predict syzbot-realization ABOVE
the reachability + v0 confounds? The final answer to the three-week g_A question.

NAIVE test is DELIBERATELY NOT COMPUTED (decision, 2026-07-20): a naive corr(g_A, realization) is spuriously
high (both driven by syzbot-reachability) → it would anchor us to a false signal. We never look at it.

CONFOUND (why controlled): syzbot only fuzzes syscall-reachable code. g_A-high subsystems (net-stack) are
ALSO syscall-reachable → a naive g_A↔realization correlation is common-cause, not causation. Also value=v0·g_A
→ control v0 too. Test = WITHIN the reachable stratum (holds reachability ~constant), PARTIAL on v0.

reachability proxy = subsystem-type (path-based domain knowledge, INDEPENDENT of syzbot). Coarse (drivers is
heterogeneous — some reachable via ioctl/USB-fuzz); flagged. realization = syzbot DIRECT sha-match (879 CVEs).
"""
from __future__ import annotations

from .pass2_kernel import build
from .wire_core import overlap_graph, pagerank, subsystem_v0, _spearman, _ga_excluded, reach_class

MIN_CVE = 5          # elements below this have a too-noisy realization-rate (0/1); excluded from the correlation


def _rank(v):
    order = sorted(range(len(v)), key=lambda i: v[i])
    rk = [0.0] * len(v)
    i = 0
    while i < len(v):
        j = i
        while j + 1 < len(v) and v[order[j + 1]] == v[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            rk[order[k]] = avg
        i = j + 1
    return rk


def _pearson(x, y):
    n = len(x)
    mx, my = sum(x) / n, sum(y) / n
    num = sum((x[i] - mx) * (y[i] - my) for i in range(n))
    dx = sum((x[i] - mx) ** 2 for i in range(n)) ** 0.5
    dy = sum((y[i] - my) ** 2 for i in range(n)) ** 0.5
    return num / (dx * dy) if dx and dy else 0.0


def _resid_on(y, x):
    """Residual of y after regressing on single predictor x (rank space)."""
    n = len(x)
    mx, my = sum(x) / n, sum(y) / n
    vx = sum((xi - mx) ** 2 for xi in x)
    b = (sum((x[i] - mx) * (y[i] - my) for i in range(n)) / vx) if vx else 0.0
    a = my - b * mx
    return [y[i] - (a + b * x[i]) for i in range(n)]


def partial_corr(x, y, z):
    """Spearman partial correlation of x,y controlling for z (rank-residualize both on z)."""
    rx, ry, rz = _rank(x), _rank(y), _rank(z)
    return _pearson(_resid_on(rx, rz), _resid_on(ry, rz))


def run():
    records, elements, mid = build()
    direct = mid["direct"]

    nodes, weight = overlap_graph(records)
    pr = pagerank(nodes, weight)
    pr_max = max(pr.values()) if pr else 1.0
    g_A = {n: pr[n] / pr_max for n in pr}

    rows = []   # (subsystem, g_A, v0, real_rate, real_count, cve_count, reach)
    for e in elements:
        if _ga_excluded(e.subsystem):
            continue
        rc = sum(1 for c in e.cve_keys if c in direct)
        v0, _, _, _ = subsystem_v0(e)
        rows.append((e.subsystem, g_A.get(e.subsystem, 0.0), v0,
                     rc / e.cve_count, rc, e.cve_count, reach_class(e.subsystem)))

    print("=" * 80)
    print("g_A EXTERNAL-VALIDITY — CONTROLLED realization test (reachability + v0). NO naive.")
    print("=" * 80)

    # --- confound confirmation: realization concentrates in the reachable stratum ---
    reach = [r for r in rows if r[6] == "reachable"]
    hard = [r for r in rows if r[6] == "hardware"]
    dm_reach = sum(r[4] for r in reach)
    dm_hard = sum(r[4] for r in hard)
    rate_reach = sum(r[4] for r in reach) / max(sum(r[5] for r in reach), 1)
    rate_hard = sum(r[4] for r in hard) / max(sum(r[5] for r in hard), 1)
    print(f"\n[confound is REAL] realization concentrates in reachable stratum:")
    print(f"    reachable: {len(reach)} elem · {dm_reach} realizations · rate={rate_reach:.3f}")
    print(f"    hardware : {len(hard)} elem · {dm_hard} realizations · rate={rate_hard:.3f}")
    print(f"    → naive corr(g_A,realization) would ride THIS (g_A-high subsystems are reachable) → controlled below")

    # --- CONTROLLED test: within reachable stratum, partial(g_A, realization | v0) ---
    strat = [r for r in reach if r[5] >= MIN_CVE]     # stable rate only
    print(f"\n[power] reachable stratum, cve_count≥{MIN_CVE}: N={len(strat)} elements"
          f" ({sum(1 for r in strat if r[4] > 0)} with ≥1 realization)")
    if len(strat) < 25:
        print(f"    ⚠ UNDERPOWERED (N<25) — result indicative, not conclusive")

    gA_s = [r[1] for r in strat]
    v0_s = [r[2] for r in strat]
    rate_s = [r[3] for r in strat]
    cnt_s = [float(r[4]) for r in strat]

    pc_rate = partial_corr(gA_s, rate_s, v0_s)      # g_A vs realization-RATE, controlling v0 (reachability by stratum)
    pc_cnt = partial_corr(gA_s, cnt_s, v0_s)        # vs realization-COUNT (cross-check)
    # variance sanity: is there g_A spread to test?
    g_spread = max(gA_s) - min(gA_s) if gA_s else 0
    print(f"\n[CONTROLLED result] within reachable stratum, PARTIAL on v0:")
    print(f"    partial-Spearman(g_A, realization_RATE  | v0) = {pc_rate:+.3f}")
    print(f"    partial-Spearman(g_A, realization_COUNT | v0) = {pc_cnt:+.3f}   (cross-check)")
    print(f"    (g_A spread in stratum = {g_spread:.2f}; v0 controlled; reachability held by stratum)")

    # --- verdict ---
    print(f"\n[VERDICT]")
    strong = abs(pc_rate) >= 0.3 and len(strat) >= 25
    weak = abs(pc_rate) < 0.15
    if pc_rate >= 0.3 and len(strat) >= 25:
        print(f"    g_A VALID — predicts realization ABOVE reachability+v0 (subsystem-overlap g_A genuinely rescued).")
    elif weak:
        print(f"    g_A SPURIOUS — no signal above reachability+v0 (the ranking-dominance was common-cause; T4 partly right).")
    else:
        print(f"    INCONCLUSIVE — partial={pc_rate:+.3f}, N={len(strat)}. Signal weak/underpowered; honest 'not-yet-shown'.")
    print(f"    (whatever the sign: because it is CONTROLLED, the answer is trustworthy — no anchoring to a false naive.)")
    print("=" * 80)
    return rows


if __name__ == "__main__":
    run()
