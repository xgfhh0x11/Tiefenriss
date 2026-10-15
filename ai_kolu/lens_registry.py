"""
lens_registry.py — multi-lens discovery registry (A2.2). EXTENSIBLE (decision §3.1).

Lens = viewpoint-framing (POINT-OF-VIEW, not output — VISION). In Pass-1 there is no prompt-content
(it produces STUB); in Pass-2 the real LLM does a separate-pass with these prompts. #Ç4 over time
deactivates a weak-lens / adds new ones → NOT a fixed-set.

MODERATE-K4: separate-lens for cleanliness+provenance; NOT for corroboration-confidence (that's correlated/fake).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Lens:
    ad: str
    viewpoint_prompt: str   # Pass-2 LLM framing (empty placeholder in Pass-1)
    aktif: bool = True
    butce_onceligi: int = 100   # low = first (when a taktik-surface gets few lenses, order comes from this; #Ç4 revise)


# Initial registry: teknik (base) + the 5 of VISION. teknik highest priority (most stress-points are teknik).
_REGISTRY: dict[str, Lens] = {
    "teknik":     Lens("teknik", "", True, 10),
    "tarihsel":   Lens("tarihsel", "", True, 20),
    "epistemik":  Lens("epistemik", "", True, 30),
    "psikolojik": Lens("psikolojik", "", True, 40),
    "sosyolojik": Lens("sosyolojik", "", True, 50),
    "felsefi":    Lens("felsefi", "", True, 60),
}


def active_lenses() -> list[Lens]:
    """Active lenses, sorted by budget-priority (a taktik-surface takes the first N)."""
    return sorted((l for l in _REGISTRY.values() if l.aktif), key=lambda l: l.butce_onceligi)


def lenses_for_tier(tier: str) -> list[Lens]:
    """
    Energy-governor mapping (CHOSEN — DECLARED, decision §3.4): tier → how many lenses.
      stratejik → all lenses · taktik → first 2 · atla → none.
    """
    act = active_lenses()
    if tier == "stratejik":
        return act
    if tier == "taktik":
        return act[:2]
    return []   # atla → A2 never runs (energy-governor)


def register(lens: Lens) -> None:
    """Add a new lens (extensibility). Called per the #Ç4 result."""
    _REGISTRY[lens.ad] = lens
