"""
pilot_fable5.py — (b) PRODUCTION Fable-5 pilot (~20 reachable surfaces) → notebook (held-out activated).

Runs the REAL operator (AnthropicBackend, claude-fable-5, effort=high) on a depth-stratified, REACHABLE-only
sample. Records with provenance=fable-5/production (SEPARATE from the earlier opus-as-operator 7 → the #Ç4
baseline can distinguish operators). Held-out f=15%, seed-invariant → the control group activates (0→~3).

REQUIRES ANTHROPIC_API_KEY in the environment. If absent → hard stop (NO opus-as-operator fallback: this run
must MEASURE production Fable-5; provenance must not blur). Cost-safety: smoke-test 1 call first, then run
surface-by-surface, STOP on any API error (don't burn the budget on a broken call-shape).

Held-out mechanics (sealed A1): the operator is exposure-BLIND (runs on all surfaces); held-out predictions
are recorded but HIDDEN at presentation (user_visible excludes them) — that is the self-fulfilling defense
(researchers never see held-out predictions → can't act on them → clean base-rate). reachable-only because
#Ç4 realization (syzbot) is only meaningful in the reachable zone.
"""
from __future__ import annotations

import os

from .ongoru_defteri import OngoruDefteri, DEFTER_YOLU_DEFAULT
from .llm_operator import AnthropicBackend, run_operator, build_prompt
from .veri_bridge import veri_contexts
from .yayim import emit_batch

PROVENANCE_FABLE = "operator=fable-5, production=true (pilot 2026-07)"
N_STRAT = 8       # ~8 stratejik (6 lenses each) + ~8 taktik (2 each). atla=0 lenses (produce nothing → skipped).
N_TAK = 8


def _require_key():
    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        raise SystemExit("STOP: ANTHROPIC_API_KEY not in env. No fallback to Opus-as-operator (provenance). "
                         "Provide the key to the Bash-environment (shell profile / inline), then run again.")


def select_pilot_surfaces() -> list:
    """reachable-only, depth-stratified: top N_STRAT stratejik + top N_TAK taktik (depth-sorted contexts)."""
    ctxs = [c for c in veri_contexts() if c.places_sample and c.places_sample[0] == "reachable"]
    strat = [c for c in ctxs if c.tier == "stratejik"][:N_STRAT]
    tak = [c for c in ctxs if c.tier == "taktik"][:N_TAK]
    return strat + tak


def smoke_test() -> bool:
    """1 surface × 1 lens live call — verify the Fable-5 call-shape works before the full ~64-call run."""
    _require_key()
    surf = select_pilot_surfaces()
    if not surf:
        raise SystemExit("no pilot-surface selected.")
    ctx = surf[0]
    backend = AnthropicBackend(effort="high")
    raw = backend.complete(ctx, "teknik")
    print(f"[smoke] {ctx.surface_id} × teknik → {len(raw)} char raw; first-120: {raw[:120]}")
    return raw.strip().startswith("[")   # valid JSON-array shape


def run_pilot(defter_path: str = DEFTER_YOLU_DEFAULT, smoke_first: bool = True) -> tuple:
    """Full pilot: smoke-test → operator on each surface → emit (provenance=fable-5) → save. Stop on API error."""
    _require_key()
    if smoke_first and not smoke_test():
        raise SystemExit("smoke-test did not return a JSON-array → call-shape broken, STOP (protect budget).")

    defter = OngoruDefteri.load(defter_path)
    backend = AnthropicBackend(effort="high")
    surfaces = select_pilot_surfaces()
    all_cands = []
    for i, ctx in enumerate(surfaces, 1):
        try:
            cands = run_operator(ctx, backend, ctx.tier)
        except Exception as ex:   # API rate-limit/error → STOP, report (don't burn budget)
            print(f"[{i}/{len(surfaces)}] {ctx.surface_id}: API ERROR {type(ex).__name__}: {str(ex)[:120]} → STOP")
            break
        all_cands.extend(cands)
        print(f"[{i}/{len(surfaces)}] {ctx.surface_id} ({ctx.tier}): {len(cands)} candidates")

    rep = emit_batch(defter, all_cands, created_ts="2026-07-22", provenance=PROVENANCE_FABLE)
    defter.save(defter_path)
    return defter, rep


if __name__ == "__main__":
    d, rep = run_pilot()
    print("PILOT:", rep["counts"])
