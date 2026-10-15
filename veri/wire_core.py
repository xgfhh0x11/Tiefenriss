"""
wire_core.py — FEED the sealed core. VALUE MODEL (decided 2026-07-20, after the controlled realization test):

  (a) g_A DROPPED from kernel value. The controlled realization test showed subsystem-overlap g_A is externally
      HOLLOW (its in-sample ranking-dominance was common-cause with reachability; partial(g_A,realization|v0,reach)≈0,
      robust). Across three rounds (CWE-edge hub / file-co-occ dead / overlap hollow) g_A never showed external
      validity → value is v0-DOMINANT. The adapter feeds g_A=1, g_B=0 → the sealed core computes v = v0·(1+w·0) = v0.
      CORE UNTOUCHED (it still evaluates v = v0·(g_A+w·g_B); we just supply the identity g_A).

  (c) REACHABILITY = a SEPARATE axis (NOT a value multiplier). It routes (reachable→machine-#Ç4, hardware→human-arm)
      and prioritizes, but is never multiplied into value (that would be reachability-noise / partly circular w/ syzbot).

The overlap-graph / PageRank functions remain below — NOT used in kernel value anymore; kept for the realization
audit (realization_test.py) and for possibly revisiting g_A in other domains. Element = subsystem.
"""
from __future__ import annotations

from collections import Counter, defaultdict

from cekirdek.core import CoreParams, evaluate, opening
from cekirdek.model import ElementProfile, GraphPosition, Signal
from adapter.ruler import v0_for
from .record import KERNEL_PROFILE
from .pass2_kernel import build

# depth-calibration stance (percentile-anchored, mirrors adapter/params.py; SELECTED):
STRAT_PCT = 90        # stratejik: deep-look at the top-10% by G
TAKTIK_PCT = 75       # taktik floor: bottom-75% atla, 75-90 taktik
K_SPAN = 2.2          # k scaled so the p75→p90 band spans ~this many sigmoid-units (scale-adaptive)

NOW_YEAR = 2026.55
V0_UNKNOWN = 0.25                        # ruler's no_cwe/blind anchor — OPEN CVEs shrink toward this
GA_EXCLUDE_PREFIXES = ("include/",)      # header dirs (kept for the audit graph)

# syscall/userspace-reachable top-levels (independent of syzbot). The reachability AXIS (decision-c).
REACHABLE_TOPS = {"net", "fs", "mm", "kernel", "ipc", "security", "block", "crypto", "io_uring", "virt", "lib"}


def reach_class(subsystem: str) -> str:
    return "reachable" if subsystem.split("/")[0] in REACHABLE_TOPS else "hardware"


def _ga_excluded(subsystem: str) -> bool:
    return any(subsystem.startswith(p) for p in GA_EXCLUDE_PREFIXES)


# ---------------------------------------------------------------------------
# v0 DENSITY aggregation — coverage-shrunk mean of per-CVE v0 (THE value signal)
# ---------------------------------------------------------------------------
def subsystem_v0(element) -> tuple[float, float, float, str]:
    """→ (v0, mean_measured, coverage, provenance). Coverage-shrunk mean of per-CVE v0 (size-independent;
    OPEN shrinks toward V0_UNKNOWN, marked). Discipline: reads element.cwe.measured() (barrier)."""
    if not element.cwe.is_measured():
        return V0_UNKNOWN, V0_UNKNOWN, 0.0, "no_cwe"
    d = element.cwe.measured()
    dist, measured_n, total = d["distribution"], d["measured_n"], d["total"]
    if measured_n == 0:
        return V0_UNKNOWN, V0_UNKNOWN, 0.0, "no_cwe"
    s = sum(cnt * v0_for([cwe])[0] for cwe, cnt in dist.items())
    mean_measured = s / measured_n
    coverage = measured_n / total
    return coverage * mean_measured + (1.0 - coverage) * V0_UNKNOWN, mean_measured, coverage, "density"


# ---------------------------------------------------------------------------
# overlap-graph / PageRank — AUDIT ONLY (g_A dropped from value; used by realization_test)
# ---------------------------------------------------------------------------
def overlap_graph(records) -> tuple[set, dict]:
    nodes: set = set()
    weight: dict[tuple, float] = defaultdict(float)
    for r in records:
        a = r.field("subsystems_full")
        subs = sorted({s for s in (a.value if (a and a.is_measured()) else []) if not _ga_excluded(s)})
        for s in subs:
            nodes.add(s)
        for i in range(len(subs)):
            for j in range(i + 1, len(subs)):
                weight[(subs[i], subs[j])] += 1.0
    return nodes, weight


def pagerank(nodes: set, weight: dict, damping: float = 0.85, iters: int = 100) -> dict:
    nodes = list(nodes)
    N = len(nodes)
    if N == 0:
        return {}
    adj: dict = defaultdict(list)
    deg: dict = defaultdict(float)
    for (a, b), w in weight.items():
        adj[a].append((b, w)); adj[b].append((a, w))
        deg[a] += w; deg[b] += w
    pr = {n: 1.0 / N for n in nodes}
    base = (1.0 - damping) / N
    for _ in range(iters):
        nxt = {n: base for n in nodes}
        dangling = damping * sum(pr[n] for n in nodes if deg[n] == 0) / N
        for n in nodes:
            if deg[n] == 0:
                continue
            share = damping * pr[n] / deg[n]
            for (m, w) in adj[n]:
                nxt[m] += share * w
        for n in nodes:
            nxt[n] += dangling
        pr = nxt
    return pr


def _spearman(xs: list[float], ys: list[float]) -> float:
    def ranks(v):
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
    rx, ry = ranks(xs), ranks(ys)
    n = len(xs)
    mx, my = sum(rx) / n, sum(ry) / n
    num = sum((rx[i] - mx) * (ry[i] - my) for i in range(n))
    dx = sum((rx[i] - mx) ** 2 for i in range(n)) ** 0.5
    dy = sum((ry[i] - my) ** 2 for i in range(n)) ** 0.5
    return num / (dx * dy) if dx and dy else 0.0


# ---------------------------------------------------------------------------
# element → ElementProfile (v = v0; g_A=1 identity; reachability carried separately)
# ---------------------------------------------------------------------------
def _cve_year(cve: str) -> float:
    try:
        return float(cve.split("-")[1])
    except Exception:
        return NOW_YEAR


def build_profiles():
    records, elements, mid = build()
    direct = mid["direct"]      # syzbot direct-matched CVEs (reachability EVIDENCE, not a value input)

    profiles = []
    for e in elements:
        v0, mean_measured, coverage, v0_status = subsystem_v0(e)
        real_count = sum(1 for c in e.cve_keys if c in direct)
        prof = ElementProfile(
            v0=v0,
            graph_pos=GraphPosition(g_A=1.0, g_B=0.0),   # decision-a: g_A=1 identity → v = v0. CORE UNTOUCHED.
            signals=[Signal(t=_cve_year(c)) for c in e.cve_keys],
            spread_count=0,                               # ρ from overlap dropped with g_A; deferred-C
            element_id=e.subsystem,
        )
        profiles.append((e, prof, v0_status, coverage, mean_measured, reach_class(e.subsystem), real_count))
    return records, elements, profiles


# ---------------------------------------------------------------------------
# (C1) depth-calibration — percentile-anchored (data-derived, mirrors adapter/params.py)
# ---------------------------------------------------------------------------
def _pct(sorted_vals, p):
    if not sorted_vals:
        return 0.0
    return sorted_vals[min(len(sorted_vals) - 1, int(p / 100.0 * len(sorted_vals)))]


def calibrate_params(Gs, base):
    """θ=G_p90, tier-thresholds from opening() at G_p75/G_p90. k scale-ADAPTIVE (p75→p90 band ~K_SPAN units).
    Percentile-anchored (SELECTED stance p90/p75), values DATA-DERIVED (not declared)."""
    pos = sorted(g for g in Gs if g > 1e-9)
    g_taktik, g_strat = _pct(pos, TAKTIK_PCT), _pct(pos, STRAT_PCT)
    k = K_SPAN / max(g_strat - g_taktik, 1e-9)     # adaptive: fits the sigmoid to THIS G-distribution
    cal = CoreParams(theta=g_strat, k=k, alpha=base.alpha, beta=base.beta, gate_p=base.gate_p)
    cal = CoreParams(theta=g_strat, k=k, alpha=base.alpha, beta=base.beta, gate_p=base.gate_p,
                     tier_taktik_esik=opening(g_taktik, cal), tier_stratejik_esik=opening(g_strat, cal))
    return cal, {"G_p75": g_taktik, "G_p90_theta": g_strat, "k": k}


# ---------------------------------------------------------------------------
# scored_surfaces — clean API for the AI-arm bridge (no printing)
# ---------------------------------------------------------------------------
def scored_surfaces() -> list[dict]:
    """Depth-calibrated kernel surfaces for AI-arm consumption. Returns dicts, depth-sorted. No print, no LLM."""
    records, elements, profiles = build_profiles()
    surf0 = [x for x in profiles if not _ga_excluded(x[0].subsystem)]
    base = CoreParams(alpha=1.0, beta=1.0)
    Gs = [evaluate(x[1], NOW_YEAR, base).tension for x in surf0]
    cal, _anch = calibrate_params(Gs, base)

    out = []
    for (e, prof, v0st, cov, mm, reach, rc) in surf0:
        d = evaluate(prof, NOW_YEAR, cal)
        cwe_mode, cwe_dist = "OPEN", {}
        if e.cwe.is_measured():
            cwe_dist = e.cwe.measured()["distribution"]
            if cwe_dist:
                cwe_mode = max(cwe_dist, key=cwe_dist.get)
        years = [int(c.split("-")[1]) for c in e.cve_keys if c.split("-")[1].isdigit()]
        span = f"{min(years)}..{max(years)}" if years else "?"
        out.append({
            "subsystem": e.subsystem, "depth": d.depth, "tier": d.tier, "reach": reach,
            "v0": prof.v0, "pi": d.persistence, "cve_count": e.cve_count, "coverage": cov,
            "cwe_mode": cwe_mode, "cwe_dist": cwe_dist, "is_interface": e.is_interface,
            "real_count": rc, "span": span,
        })
    out.sort(key=lambda r: r["depth"], reverse=True)
    return out


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------
def report():
    records, elements, profiles = build_profiles()
    surf0 = [x for x in profiles if not _ga_excluded(x[0].subsystem)]   # (e,prof,v0st,cov,mm,reach,rc)

    # value model: g_A=1 → v=v0; G = v^gate_p · α·π (ρ=0). π-RAW = CVE-accumulation (decision-C).
    base = CoreParams(alpha=1.0, beta=1.0)          # gate_p=2 (hard-veto), lam=0.05; G is θ/k-independent
    Gs = [evaluate(x[1], NOW_YEAR, base).tension for x in surf0]
    cal, anch = calibrate_params(Gs, base)

    rows = []
    for x in surf0:
        d = evaluate(x[1], NOW_YEAR, cal)
        pi = d.persistence
        rows.append((x[0], x[1], d, x[5], x[6], pi))   # (e, prof, d, reach, real_count, π)
    N = len(rows)

    print("=" * 84)
    print("WIRE-CORE v4 — DEPTH = v0-density × π-raw, PERCENTILE-CALIBRATED (g_A dropped · reach separate)")
    print("=" * 84)
    print(f"\n[calibration] percentile-anchored, DATA-DERIVED (not declared): "
          f"θ=G_p90={anch['G_p90_theta']:.2f}, G_p75={anch['G_p75']:.2f}, k={anch['k']:.3f} (scale-adaptive)")
    print(f"[value] v=v0 (g_A=1 identity, v==v0: {all(abs(x[1].v0-x[2].value)<1e-9 for x in rows)}); "
          f"G=v^2·π (ρ dropped); π=CVE-accumulation (raw)")

    # --- [1] TOP SURFACES by DEPTH ---
    by_d = sorted(rows, key=lambda r: r[2].depth, reverse=True)
    print(f"\n[1] TOP SURFACES by DEPTH  [n={N}]   (depth | tier | v0 | π | reach | subsystem)")
    for (e, prof, d, reach, rc, pi) in by_d[:14]:
        seam = " ⟂SEAM" if e.is_interface else ""
        rl = "REACH" if reach == "reachable" else "hardw"
        print(f"    D={d.depth:.3f} {d.tier:9s} v0={prof.v0:.2f} π={pi:6.1f} {rl}  {e.subsystem}{seam}")
    print(f"    ...bottom (single-CVE flukes): "
          + ", ".join(f"{r[0].subsystem}(D={r[2].depth:.2f},π={r[5]:.1f})" for r in by_d[-3:]))

    # --- [2] TIER DISTRIBUTION (target ~75/15/10, not degenerate) ---
    tier_ct = Counter(r[2].tier for r in rows)
    print(f"\n[2] TIER DISTRIBUTION: {dict(tier_ct)}  "
          f"(atla {100*tier_ct['atla']//N}% / taktik {100*tier_ct['taktik']//N}% / stratejik {100*tier_ct['stratejik']//N}%)")

    # --- [3] INVARIANT: π=pressure ≠ reachability=routing (no re-injection into value) ---
    dvals = [r[2].depth for r in rows]
    rbin = [1.0 if r[3] == "reachable" else 0.0 for r in rows]
    sp_dr = _spearman(dvals, rbin)
    hi_hard = [r for r in by_d[:40] if r[3] == "hardware"]   # high-depth hardware subsystems
    dn = next((r for r in rows if r[0].subsystem == "drivers/net"), None)
    print(f"\n[3] INVARIANT (π=pressure ≠ reachability=routing):")
    if dn:
        dn_rank = [i for i, r in enumerate(by_d) if r[0].subsystem == "drivers/net"][0] + 1
        print(f"    drivers/net (high-π hardware): depth-rank #{dn_rank}, tier={dn[2].tier}, reach=HARDWARE→human-arm"
              f" (depth-high AND human-routed = consistent, NOT reachability-in-value)")
    print(f"    high-depth(top-40) but HARDWARE-routed: {len(hi_hard)}  "
          f"e.g. {', '.join(r[0].subsystem for r in hi_hard[:5])}")
    print(f"    Spearman(depth, reachable) = {sp_dr:+.3f} → "
          f"{'π IS a reachability-proxy (LEAK!)' if sp_dr > 0.7 else 'π not a reachability-proxy (invariant holds)'}")

    # --- [4] discipline ---
    st_ct = Counter(x[2] for x in profiles if not _ga_excluded(x[0].subsystem))
    print(f"\n[4] discipline")
    print(f"    π counts ALL CVE-signals (CWE-status-independent → no leak; v0 marks OPEN as 0.25)")
    print(f"    v0 provenance: {dict(st_ct)} (no_cwe=fully-OPEN, no fabrication) · percentile-anchor data-derived (not declared)")
    print("=" * 84)
    return rows


if __name__ == "__main__":
    report()
