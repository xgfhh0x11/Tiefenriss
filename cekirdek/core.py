"""
cekirdek/core.py
================
The computation engine of the core — a faithful execution of the v2.1 formalization.

Core formula (v2.1 §13):
    D(s,t) = D_max · σ(k·(G − θ))
    G(s,t) = v · (α·π + β·ρ)          [gate × alternative paths]
    v      = v0 · (g_A + w·g_B)       [static ruler × composite graph-position]
    π(s,t) = Σ σ_bin · e^(−λ(t−τ))    [damped persistence accumulation]

Parameter split (v2.1 §8 — CORE PRINCIPLE):
    EPISTEMIC (ruler, slow/fixed) : λ, v0 arrive as input
    POLITICAL (strategy, adaptive): θ, k, α, β, w, D_max  → CoreParams

This file stays FAITHFUL to the formalization, ADDS nothing to it. The theory is done; this is execution.
"""

from __future__ import annotations
import math
from dataclasses import dataclass

from .model import ElementProfile, DepthDecision


# ---------------------------------------------------------------------------
# POLITICAL PARAMETERS — operational choices, adaptive (v2.1 §7-8)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class CoreParams:
    """
    The POLITICAL parameters of the core. They do not define "reality" (that is epistemic),
    they define "what we will do" — tunable per context.

    The v2.1 rationale for each:

    lam (λ)   : damping/forgetting rate. EPISTEMIC-INFRASTRUCTURE really (a ruler) — but
                kept here in the computation because the π calculation needs it.
                Must stay FIXED: if it changes, the meaning of the past shifts (v2.1 K1).
                Small λ → long memory; large λ → forgets quickly.
    w         : g_B weight (how much to trust the derived graph-signal). POLITICAL.
                w=0 → pure Type A (Option 1); w>0 → A+B mixed-status.
    alpha (α) : weight of the persistence axis (how important repetition is). POLITICAL.
    beta (β)  : weight of the spread axis (how important spread is). POLITICAL.
                NOTE: α,β CANNOT be calibrated independently — π,ρ are orthogonal-ish,
                there is positive correlation (v2.1 §10 orthogonality note).
    theta (θ) : opening threshold. POLITICAL — "at what point do I act".
                Closed in noise, open under real tension.
    k         : sigmoid sharpness. How hard the transition is.
    d_max     : maximum processing-depth (energy-economy ceiling).

    Threshold values (for the tier labels — coarsening, not the core's decision):
    tier_taktik_esik    : if depth is above this value, at least "taktik"
    tier_stratejik_esik : if depth is above this value, "stratejik"
    """
    lam: float = 0.05          # λ — damping (long-memory default)
    w: float = 0.5             # g_B weight (A+B, labeled)
    alpha: float = 1.0         # persistence-axis weight
    beta: float = 1.0          # spread-axis weight
    theta: float = 0.30        # opening threshold
    k: float = 8.0             # sigmoid sharpness
    d_max: float = 1.0         # depth ceiling
    gate_p: float = 2.0        # gate exponent (v^p) — HARD VETO. If p>1 a low value
                               # CANNOT be compensated by high persistence. Rationale: OPEN QUESTION #1
                               # decision (A). Early-warning comes not from persistence (π) but from
                               # position movement (g); the gate must stay closed to persistence.

    # tier coarsening thresholds (interpretation layer, not computation)
    tier_taktik_esik: float = 0.15
    tier_stratejik_esik: float = 0.55

    # spread normalization: ρ = spread_count / (spread_count + rho_scale)
    # compresses the raw count into [0,1), saturating. rho_scale = "half-saturation" point.
    rho_scale: float = 3.0


# ---------------------------------------------------------------------------
# π — DAMPED PERSISTENCE ACCUMULATION (v2.1 §2)
# ---------------------------------------------------------------------------
def persistence(profile: ElementProfile, now: float, lam: float) -> float:
    """
    π(s,t) = Σ_τ σ_bin(s,τ) · e^(−λ(t−τ))

    A discrete sum instead of an integral — because signals are discrete pulses (each CVE/advisory
    a pulse). Since σ_bin is binary, each pulse contributes only e^(−λ·age).

    - One-off signal → fades away (age large → e^(−λ·age) small).
    - Recurring signal → accumulates, beats the damping.

    now : the current time (t). age = now − signal.t.
    Future signals (t > now) are ignored (causality).
    """
    total = 0.0
    for sig in profile.signals:
        age = now - sig.t
        if age < 0:
            continue  # future signal — causality, skip
        total += math.exp(-lam * age)
    return total


# ---------------------------------------------------------------------------
# ρ — SPREAD (v2.1 Pressure 2)
# ---------------------------------------------------------------------------
def spread(profile: ElementProfile, rho_scale: float) -> float:
    """
    ρ = spread (space axis). "In how many SEPARATE places it appeared" — different from repetition (π, time).

    Compress the raw count into a saturating [0,1) value:
        ρ = spread_count / (spread_count + rho_scale)

    Why saturating: the 1 subsystem → 10 subsystem difference matters; 100 → 110 does not.
    rho_scale = half-saturation point (ρ = 0.5 when spread_count == rho_scale).
    """
    c = max(0, profile.spread_count)
    return c / (c + rho_scale)


# ---------------------------------------------------------------------------
# v — VALUE (composite gate) (v2.1 §1, §11)
# ---------------------------------------------------------------------------
def value(profile: ElementProfile, w: float) -> float:
    """
    v = v0 · (g_A + w·g_B)

    v0    : static ruler (epistemic-infrastructure).
    g_A   : measured graph-position (Type A, MEASURED).
    g_B   : derived graph-position (Type B, DERIVED, thresholded).
    w     : g_B weight (political).

    Value is a GATE (v2.1 §4): if v ≈ 0, then no matter how much persistence/spread there is
    tension ≈ 0 (noise). v has veto power — that is why it is a multiplier in G.

    NOTE: This function returns the RAW v (transparency — let the real value show).
    Gate HARDNESS (the v^p exponent, OPEN QUESTION #1 decision A) is applied in tension(),
    not here. This way we see both the raw value and the gate-effect separately.
    """
    g = profile.graph_pos.g_A + w * profile.graph_pos.g_B
    return profile.v0 * g


# ---------------------------------------------------------------------------
# G — TENSION (gate × alternative paths) (v2.1 §3)
# ---------------------------------------------------------------------------
def tension(v: float, pi: float, rho: float,
            alpha: float, beta: float, gate_p: float = 1.0) -> float:
    """
    G = v^p · (α·π + β·ρ)

    Structure: one GATE (v^p, a multiplier) × two ALTERNATIVE PATHS (π and ρ, a weighted SUM).
    - NOT a product, NOT a pure sum — the right combination of the two (v2.1 §3).
    - v^p multiplier: if valueless, nothing matters (gate closed).
    - π+ρ sum: repetition OR spread alone can carry value
      (a deep/narrow type in a single subsystem still lives with high π and ρ~0).

    GATE EXPONENT (gate_p, OPEN QUESTION #1 decision A — HARD VETO):
    if p > 1, a low v CANNOT be compensated by high π. v=0.02, p=2 → v^p=0.0004:
    the gate effectively closes, and whatever the persistence G≈0. Rationale: "valueless but
    persistent" covers two cases — (i) genuine busy-noise, (ii) not-yet-visible
    value. π CANNOT tell them apart (high in both). What separates them is the MOVEMENT of g:
    if real value is emerging the surface drifts toward a valuable neighborhood → g↑ → v↑ → the gate
    opens BY ITSELF. In fake noise g stays constant-low → it stays closed.
    So early-warning comes through the MEASURED channel (g), not the FORCED channel (π pushing
    the gate). p>1 enforces this discipline: persistence cannot force the gate.
    p=1 → old behavior (no exponent).
    """
    gate = v ** gate_p
    return gate * (alpha * pi + beta * rho)


# ---------------------------------------------------------------------------
# D — OPENING FUNCTION (the core itself) (v2.1 §4, K5)
# ---------------------------------------------------------------------------
def _sigmoid(x: float) -> float:
    """Numerically stable logistic sigmoid."""
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    else:
        z = math.exp(x)
        return z / (1.0 + z)


def opening(G: float, p: CoreParams) -> float:
    """
    D = D_max · σ(k·(G − θ))              [v2.1 K5 — sigmoid threshold]

    NOT saturating (not v1's G/(1+G)) — a sigmoid, because:
    - In noise (G < θ) it stays CLOSED (prevents early opening).
    - Under real tension (G > θ) it opens fast.
    - θ = threshold (political), k = transition sharpness.
    """
    return p.d_max * _sigmoid(p.k * (G - p.theta))


# ---------------------------------------------------------------------------
# tier — interpretation layer (NOT the core's decision, coarsening)
# ---------------------------------------------------------------------------
def _classify_tier(depth: float, p: CoreParams) -> str:
    """
    Split the continuous depth into 3 coarse buckets for human reading. This is a LABEL,
    the core's actual decision is continuous (depth). (v2.1 §4 quadrant)
    """
    if depth >= p.tier_stratejik_esik:
        return "stratejik"
    if depth >= p.tier_taktik_esik:
        return "taktik"
    return "atla"


# ---------------------------------------------------------------------------
# CORE — full evaluation (profile → depth decision)
# ---------------------------------------------------------------------------
def evaluate(profile: ElementProfile, now: float, p: CoreParams) -> DepthDecision:
    """
    The core's single general entry point: pass in a profile, get a processing-depth.

    Element-agnostic: profile.element_id IS NOT CONSIDERED. The core sees only
    v0, graph-position, signals, spread — it does not know WHAT the element is.

    Flow:
        π  = persistence(signals, now, λ)
        ρ  = spread(spread_count)
        v  = value(v0, graph_pos, w)          [raw value, transparent]
        G  = tension(v, π, ρ, α, β, gate_p)    [gate v^p — hard veto]
        D  = opening(G, θ, k, D_max)
    """
    pi = persistence(profile, now, p.lam)
    rho = spread(profile, p.rho_scale)
    v = value(profile, p.w)
    G = tension(v, pi, rho, p.alpha, p.beta, p.gate_p)
    D = opening(G, p)
    tier = _classify_tier(D, p)

    return DepthDecision(
        depth=D,
        tier=tier,
        tension=G,
        value=v,
        persistence=pi,
        spread=rho,
    )
