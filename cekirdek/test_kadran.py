"""
test_kadran.py
==============
Validates the core's QUADRANT behavior with synthetic profiles (v2.1 §4).

Expected quadrant:
    value HIGH + persistence HIGH  → stratejik vein (open deep)
    value HIGH + one-off           → taktik (open but do not accumulate)
    value LOW  + (any)             → atla (gate closed, noise)

This is a proof: does the code execute the formula correctly, does the quadrant come out?
NO real data — pure synthetic, we test the core in isolation.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cekirdek.model import ElementProfile, GraphPosition, Signal
from cekirdek.core import CoreParams, evaluate


def make_signals(times):
    return [Signal(t=t) for t in times]


def show(label, profile, now, p):
    d = evaluate(profile, now, p)
    print(f"{label:34s} | v={d.value:5.3f}  π={d.persistence:5.2f}  "
          f"ρ={d.spread:4.2f}  G={d.tension:5.3f}  D={d.depth:5.3f}  → {d.tier}")
    return d


def main():
    p = CoreParams()
    now = 100.0  # current time

    print("=" * 92)
    print(f"CORE QUADRANT TEST   (λ={p.lam}, w={p.w}, α={p.alpha}, β={p.beta}, "
          f"θ={p.theta}, k={p.k}, gate_p={p.gate_p})")
    print("HARD VETO (OPEN QUESTION #1 → A): gate v^p, persistence cannot compensate a low value.")
    print("=" * 92)

    # --- QUADRANT 1: valuable + persistent (recent recurring signals) ---
    # high graph-position, 6 signals in the last 20 days → π high
    q1 = ElementProfile(
        v0=0.9,
        graph_pos=GraphPosition(g_A=0.8, g_B=0.6),
        signals=make_signals([82, 86, 90, 94, 97, 99]),
        spread_count=4,
        element_id="q1_degerli_israrli",
    )
    d1 = show("QUADRANT 1  valuable + persistent", q1, now, p)

    # --- QUADRANT 2: valuable + one-off (single old signal) ---
    # high graph-position but only 1 signal, 40 days ago → π low
    q2 = ElementProfile(
        v0=0.9,
        graph_pos=GraphPosition(g_A=0.8, g_B=0.6),
        signals=make_signals([60]),
        spread_count=1,
        element_id="q2_degerli_tekseferlik",
    )
    d2 = show("QUADRANT 2  valuable + one-off", q2, now, p)

    # --- QUADRANT 3: valueless + persistent (low graph-position, many repetitions) ---
    # low v0 and graph-position but many signals → gate closed, G≈0 expected
    q3 = ElementProfile(
        v0=0.15,
        graph_pos=GraphPosition(g_A=0.1, g_B=0.05),
        signals=make_signals([82, 86, 90, 94, 97, 99]),
        spread_count=4,
        element_id="q3_degersiz_israrli",
    )
    d3 = show("QUADRANT 3  valueless + persistent", q3, now, p)

    # --- QUADRANT 4: valueless + one-off (noise) ---
    q4 = ElementProfile(
        v0=0.1,
        graph_pos=GraphPosition(g_A=0.08, g_B=0.02),
        signals=make_signals([55]),
        spread_count=0,
        element_id="q4_gurultu",
    )
    d4 = show("QUADRANT 4  valueless + one-off", q4, now, p)

    print("=" * 92)

    # --- VALIDATION: quadrant expectations ---
    print("\nVALIDATION:")
    checks = [
        ("K1 should be stratejik (valuable+persistent, deepest)", d1.tier == "stratejik"),
        ("K1 > K2 (persistence increases depth)", d1.depth > d2.depth),
        ("K2 opens (very valuable, even one-off passes the threshold)", d2.depth > p.tier_taktik_esik),
        ("K3 atla (HARD VETO: valueless → persistence does not save it)", d3.tier == "atla"),
        ("K4 atla (noise)", d4.tier == "atla"),
        ("K1 > K3 (same persistence, value difference is decisive)", d1.depth > d3.depth),
        ("K3 ≈ K4 (after the hard veto both are gate-closed)", abs(d3.depth - d4.depth) < 0.05),
    ]
    all_ok = True
    for desc, ok in checks:
        mark = "✓" if ok else "✗ FAILED"
        if not ok:
            all_ok = False
        print(f"  {mark}  {desc}")

    print("\n" + ("ALL QUADRANTS CORRECT — the core executes the formula correctly."
                  if all_ok else "!!! QUADRANT ERROR — the core does not meet expectations."))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
