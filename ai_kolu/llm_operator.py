"""
llm_operator.py — Pass-2 REAL LLM operator (multi-lens discovery generator).

Attaches a real Claude operator to Pass-1's operator-agnostic pipeline (boundary→yayim→montaj).
Operator = the LATEST Claude (`claude-fable-5`; multi-lens discovery = the hardest reasoning, a design requirement).
The operator produces free-text; the PARSER projects it into a typed `Candidate`; the BOUNDARY disciplines it.

HONESTY-CONTRACT (Pass-2's epistemic burden): the operator names a FALSIFICATION-SIGNAL for every prediction.
  • measurable-now (surface-tier rises UP)               → signal_kind=tier_crossing (cat-1)
  • concrete-future-measurement (named detector + horizon) → signal_kind=future_detector (cat-2)
  • if no signal can be named                            → signal_kind=none (REJECTED AT BOUNDARY; the CORRECT result)
CEILING-RULE (AU-1): if the surface is already stratejik (ceiling) "tier rises up" is IMPOSSIBLE →
  tier_crossing FORBIDDEN; use cat-2 (fine/weaponization/colocation detector) or none.
The boundary also enforces this rule STRUCTURALLY (boundary ceiling-guard) — a backstop against operator lying.

Backend abstract: AnthropicBackend (LIVE) + RecordedBackend (fixture → reproducible eval/test).
One-way: ai_kolu → adapter → cekirdek. Prozessfall read-only. Does not touch the kernel.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from .ongoru_defteri import Direction, PredType
from .a2_types import Candidate, SignalKind
from .boundary import CWE_CLOSED_SET, MAX_FEASIBLE_HORIZON_DAYS
from .lens_registry import lenses_for_tier

OPERATOR_MODEL = "claude-fable-5"          # the latest Claude (design: the hardest reasoning)
OPERATOR_FALLBACK = "claude-opus-4-8"      # Fable-5 refusal-fallback (default safety)
CEILING_TIER = "stratejik"                 # the ceiling of the kernel tier-hierarchy (can't-rise-above)


# ---------------------------------------------------------------------------
# Surface context (adapter Surface → prompt-ready context). Read-only.
# ---------------------------------------------------------------------------
@dataclass
class SurfaceContext:
    surface_id: str
    cwe: str
    vp: str
    tier: str
    n_members: int
    day_span: str
    n_places: int
    places_sample: list[str]
    note: str = ""          # optional substrate-richness (veri/ bridge: reachability/CWE-distribution/depth). Empty → old behavior.

    @property
    def at_ceiling(self) -> bool:
        return self.tier == CEILING_TIER

    def as_prompt_block(self) -> str:
        block = (
            f"surface_id: {self.surface_id}\n"
            f"zafiyet-sınıfı (primary CWE): {self.cwe}\n"
            f"vendor:product (subsystem): {self.vp}\n"
            f"çekirdek-tier (ŞU AN): {self.tier}"
            f"{'  ← TAVAN (yukarı-aşamaz!)' if self.at_ceiling else ''}\n"
            f"üye-CVE sayısı (sinyal-darbeleri): {self.n_members}\n"
            f"darbe-aralığı: {self.day_span}\n"
            f"yayılım (distinct vendor:product): {self.n_places} — ör: {self.places_sample}\n"
        )
        if self.note:
            block += f"{self.note}\n"
        return block


def surface_context(surface, tier: str) -> SurfaceContext:
    """Adapter Surface (+ kernel-tier) → SurfaceContext. Read-only read."""
    days = getattr(surface, "days", []) or []
    span = f"{min(days)}..{max(days)}" if days else "?"
    places = list(getattr(surface, "places", []) or [])
    return SurfaceContext(
        surface_id=surface.sid, cwe=surface.cwe, vp=surface.vp, tier=tier,
        n_members=len(getattr(surface, "members", []) or []), day_span=span,
        n_places=len(places), places_sample=places[:6],
    )


# ---------------------------------------------------------------------------
# Lens framings (written at BUILD — lens_registry enable/priority, the text here)
# ---------------------------------------------------------------------------
LENS_FRAMINGS: dict[str, str] = {
    "teknik":     "Teknik-mercek: bu bug-sınıfının bu subsystem'deki exploit-primitive'ini düşün "
                  "(UAF→yeniden-tahsis, OOB→komşu-obje, integer-overflow→boyut-yanılgısı).",
    "tarihsel":   "Tarihsel-mercek: bu bug-türü tarihsel olarak hangi koşulda kümelenir/mutasyona uğrar? "
                  "Benzer koşul burada var mı? (fenotipik-türeme sezgisi).",
    "epistemik":  "Epistemik-mercek: burada ne 'biliniyor' sanılıyor ama VARSAYIM? Varsayımın kırıldığı "
                  "yer stres-noktası.",
    "psikolojik": "Psikolojik-mercek: savunmacı neyi 'imkansız' sayıp görmezden gelir, saldırgan neyi "
                  "önce dener?",
    "sosyolojik": "Sosyolojik-mercek: bu kod/subsystem hangi organizasyonel/topluluk dinamiğiyle üretiliyor "
                  "(hangi kör-nokta sistematik)?",
    "felsefi":    "Felsefi-mercek: bu zafiyet-sınıfının doğası hakkında hangi kavramsal çerçeve yeni bir "
                  "bakış açısı açar?",
}

_HONESTY_CONTRACT = f"""Her öngörü OPERASYONEL + YANLIŞLANABİLİR olmalı. Şu tipli-şemaya dökülemeyen aday ÜRETME.
Alanlar: pred_type ("stress_point"=düğüm | "transition"=kenar/pivot), vuln_class (CWE), mechanism,
signal_kind, falsification_method, (transition ise) target_ref, (future_detector ise) detector_name + signal_horizon_days.

DÜRÜSTLÜK-SÖZLEŞMESİ — signal_kind DÜRÜSTÇE etiketlenmeli (bu senin epistemik yükün):
  • "tier_crossing"    → surface'in çekirdek-tier'ı YUKARI aşacak (bugün ölçülebilir). AMA:
  • TAVAN-KURALI: surface zaten "stratejik" (tavan) ise tier YUKARI-AŞAMAZ → tier_crossing YASAK.
    Bunun yerine "future_detector" (ince/silahlanma/colocation detector + sınırlı ufuk) ya da "none".
  • "future_detector"  → bugün ölçemezsin ama SOMUT bir gelecek-detector + sınırlı ufuk adlayabilirsin
    (detector_name dolu, signal_horizon_days ≤ {MAX_FEASIBLE_HORIZON_DAYS}).
  • "none"             → hiçbir kontrol-edilebilir sinyal adlayamıyorsan. Bu SINIRDA REDDEDİLİR ve bu DOĞRU
    sonuç — sınanamaz-derin bir sezgiyi tier_crossing kılığına SOKMA. Mercek nereye-bak dedi; sen ne-buldun
    yaz, neden-değil.
vuln_class KAPALI-KÜME'den (v0 CWE aileleri): {sorted(CWE_CLOSED_SET)}.
Çıktı: SADECE bir JSON dizisi (aday-objeleri). Açıklama/markdown yok."""


def build_prompt(ctx: SurfaceContext, lens_name: str) -> tuple[str, str]:
    """Returns (system, user). system = contract+lens; user = surface context."""
    framing = LENS_FRAMINGS.get(lens_name, f"{lens_name}-mercek.")
    system = (
        "Sen Tiefenriss'in çok-mercek keşif operatörüsün — araştırmacının operasyonel gözünün bir merceği. "
        "Bir surface'e verilen mercekle bakıp tip-2 (öngörü) stres-noktaları ve geçişler üretirsin. "
        "Mercek BAKIŞ-AÇISI'dır, çıktı değil: çıktın %100 operasyonel + yanlışlanabilir olmalı.\n\n"
        f"MERCEK — {framing}\n\n" + _HONESTY_CONTRACT
    )
    user = "Şu surface'i bu mercekle incele ve JSON aday-dizisi üret:\n\n" + ctx.as_prompt_block()
    return system, user


# ---------------------------------------------------------------------------
# Backend abstraction
# ---------------------------------------------------------------------------
class RecordedBackend:
    """Replays recorded operator-cognition (reproducible eval/test; not LIVE)."""

    def __init__(self, recorded: dict[tuple[str, str], str]):
        self._rec = recorded

    def complete(self, ctx: SurfaceContext, lens_name: str) -> str:
        return self._rec.get((ctx.surface_id, lens_name), "[]")


class AnthropicBackend:
    """LIVE operator: the latest Claude (claude-fable-5). Non-deterministic → RecordedBackend in eval."""

    def __init__(self, model: str = OPERATOR_MODEL, effort: str = "high"):
        import anthropic  # lazy: only needed in live-production
        self._client = anthropic.Anthropic()
        self._model = model
        self._effort = effort

    def complete(self, ctx: SurfaceContext, lens_name: str) -> str:
        system, user = build_prompt(ctx, lens_name)
        # Fable-5: thinking always-on (no parameter); NO temperature; effort in output_config;
        # refusal-fallback → opus-4-8 (default). Output is free-JSON (the parser projects it).
        resp = self._client.beta.messages.create(
            model=self._model, max_tokens=8000,
            betas=["server-side-fallback-2026-06-01"],
            fallbacks=[{"model": OPERATOR_FALLBACK}],
            output_config={"effort": self._effort},
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        if resp.stop_reason == "refusal":
            return "[]"   # classifier refused → empty (honest: no production)
        return next((b.text for b in resp.content if b.type == "text"), "[]")


# ---------------------------------------------------------------------------
# Parser: free-JSON → typed Candidate. (The boundary does NOT EVALUATE yet; it only projects.)
# ---------------------------------------------------------------------------
_SIGNAL_MAP = {
    "tier_crossing": SignalKind.TIER_CROSSING,
    "future_detector": SignalKind.FUTURE_DETECTOR,
    "none": SignalKind.NONE,
}
_PRED_MAP = {"stress_point": PredType.STRESS_POINT, "transition": PredType.TRANSITION}


def parse_candidates(raw: str, ctx: SurfaceContext, lens_name: str) -> list[Candidate]:
    """Projects the operator's free-JSON into a list of Candidates. A broken-item is skipped (not-silent:
    the caller sees it in the reject-log — here only type-projection). tier_at_creation = surface-tier snapshot."""
    try:
        items = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(items, list):
        return []
    out: list[Candidate] = []
    for i, it in enumerate(items):
        if not isinstance(it, dict):
            continue
        out.append(Candidate(
            key=f"{ctx.surface_id}|{lens_name}|{i}",
            surface_id=ctx.surface_id,
            direction=Direction.ILERI,
            pred_type=_PRED_MAP.get(it.get("pred_type", "stress_point"), PredType.STRESS_POINT),
            vuln_class=str(it.get("vuln_class", "")),
            mechanism=str(it.get("mechanism", "")),
            signal_kind=_SIGNAL_MAP.get(it.get("signal_kind", "none"), SignalKind.NONE),
            falsification_method=str(it.get("falsification_method", "")),
            source_lens=lens_name,
            target_ref=it.get("target_ref"),
            detector_name=it.get("detector_name"),
            signal_horizon_days=it.get("signal_horizon_days"),
            tier_at_creation=ctx.tier,     # snapshot coming from the kernel (also needed for the ceiling-guard)
        ))
    return out


def run_operator(ctx: SurfaceContext, backend, tier: str) -> list[Candidate]:
    """Energy-governor: tier → how many lenses (lenses_for_tier). An operator-pass per lens → candidates."""
    cands: list[Candidate] = []
    for lens in lenses_for_tier(tier):
        raw = backend.complete(ctx, lens.ad)
        cands.extend(parse_candidates(raw, ctx, lens.ad))
    return cands
