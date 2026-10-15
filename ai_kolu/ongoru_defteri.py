"""
ongoru_defteri.py — PREDICTION-NOTEBOOK SCHEMA (empty, held-out channel, leak-proof).

╔══════════════════════════════════════════════════════════════════════════╗
║ WHY DAY-1 (BEFORE the AI arm is built):                                    ║
║ Few-user phase = the irreproducible CLEAN BASELINE in which self-          ║
║ fulfilling is DORMANT. That baseline can't be built later (after scaling,  ║
║ the world is dirty). Built empty NOW; fills when the AI arm arrives. İ7/#Ç4║
╚══════════════════════════════════════════════════════════════════════════╝

This file is ONLY SCHEMA + empty notebook. NO AI arm → NO filling. Does not touch the kernel.

Principles it carries (`adapter/PoC_BULGULAR.md` §AI KOLU MİMARİSİ):
  • İ2   — every prediction starts as a TYPE-2 link (status-labeled; statusless forbidden).
  • İ5   — the referee is REALITY: a prediction "realized" only when a CVE appears on the surface and g rises (measured).
  • İ7   — HELD-OUT channel: a segment of predictions is NOT SHOWN to the user → self-fulfilling
           control-group. Must be LEAK-PROOF (if it leaks the control is contaminated, measurement meaningless).
  • İ9a  — usage/engagement is NEVER counted as realization (only reality: CVE+g). At code-level
           `Realization` is set only from reality; there is NO engagement field (deliberate).
  • #Ç4  — highlighted vs held-out confirmation-rate difference (self-fulfilling coefficient). `confirmation_gap()`.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum


# ---------------------------------------------------------------------------
# ENUMs — fixed vocabulary (status-discipline embedded in the types)
# ---------------------------------------------------------------------------
class Direction(str, Enum):
    """Scan-direction (İ4). surface→ileri = discovery; target→geri = operation (TTD-travel)."""
    ILERI = "ileri"       # surface → path (discovery)
    GERI = "geri"         # target → path (operation)


class LinkStatus(str, Enum):
    """Link status (İ2). A prediction starts TYPE-2; when realized it becomes TYPE-1 (enters the kernel)."""
    TIP_2 = "tip_2"       # prediction — unverifiable, does NOT ENTER the kernel
    TIP_1 = "tip_1"       # measured/verified — enters the kernel


class Exposure(str, Enum):
    """
    Exposure (İ7). Set at CREATION, IMMUTABLE (leak-proofness = immutability).
      HIGHLIGHTED — shown to the user (attention-steering possible → OPEN to self-fulfilling).
      HELD_OUT    — hidden control group; NEVER shown to the user, tested against reality in the dark.
    """
    HIGHLIGHTED = "highlighted"
    HELD_OUT = "held_out"


class Realization(str, Enum):
    """
    Realization-state (İ5). Set ONLY from reality. REALIZATION CRITERION (2026-07-16 decision):
    did the surface rise above the kernel's tier-boundary from its tier at prediction-moment (verdict FROM THE KERNEL,
    no separate realization-threshold is INVENTED). Degree (how-many-tiers) is optional metadata.
      BEKLIYOR    — not yet realized, WITHIN the horizon (NOTE: NOT "wrong" — not negative evidence, #Ç3 asymmetry).
      GERCEKLESTI — kernel-tier rose up → measured → promoted to TYPE-1.
      CURUDU      — active/explicit dis-confirmation (rare; "pending" ≠ "decayed").
      LAPSED      — realization-horizon EXCEEDED, no signal. NOT CURUDU (not a false-refute), but
                    the ONLY legitimate source of falsifiability: held-out-LAPSED = quasi-clean negative (#Ç4 can't be
                    measured without it). PERMANENT record — not deleted, only a state-transition.
    """
    BEKLIYOR = "bekliyor"
    GERCEKLESTI = "gerceklesti"
    CURUDU = "curudu"
    LAPSED = "lapsed"


class PredType(str, Enum):
    """Prediction-atom type (A2.4): path = node-atoms + edge-atoms; both are gated."""
    STRESS_POINT = "stress_point"   # node — surface vulnerability-claim
    TRANSITION = "transition"       # edge — transition/pivot claim (speculative exploit-logic)


class MeasurementCategory(str, Enum):
    """Measurement-category (A2.3 THREE-WAY). Cat-3 (measurement-undefined) is never recorded (rejected at the boundary)."""
    SIMDI = "1"              # reduces to tier-crossing → the time-gate tests it now
    PENDING_DETECTOR = "2"   # concrete-future-measurement → tested once that detector is built


# ---------------------------------------------------------------------------
# RECORD — a single prediction
# ---------------------------------------------------------------------------
@dataclass
class Ongoru:
    """
    A single prediction record. `exposure` is set at CREATION and NOT CHANGED (leak-proofness).
    `realization`/`realized_ts` start empty; updated only by REALITY (İ5).

    CAUTION: there is DELIBERATELY NO engagement/usage field (İ9a). A prediction's "value"
    depends on confirmation, and confirmation only on reality — NOT clicks/being-found-useful.
    """
    pred_id: str                      # stable unique id (assigned on the production side)
    surface_id: str                   # target surface (adapter surface.sid)
    direction: Direction              # İ4 scan-direction
    content: str                      # prediction content (path/link description)
    created_ts: str                   # production timestamp (ISO or day-int str); caller supplies it (now() not embedded)
    exposure: Exposure                # İ7 — set at CREATION, immutable
    status: LinkStatus = LinkStatus.TIP_2        # İ2 — a prediction starts TYPE-2
    realization: Realization = Realization.BEKLIYOR   # İ5 — starts empty
    realized_ts: str | None = None    # realization/decay/lapse timestamp; reality sets it, starts empty
    horizon_days: int | None = None   # CHOSEN realization-horizon (2026-07-16). Nominal-now; PER-DIRECTION
                                      # flexible (ileri≠geri); percentile-calibrated live. If horizon exceeded with no signal → LAPSED.
    tier_at_creation: str | None = None   # prediction-moment kernel-tier snapshot (against params-drift;
                                          # realization = current-tier > this, measured on the SAME params base)
    # ── A2 fields (2026-07-18, all defaulted → A1 records/tests don't break) ──
    pred_type: PredType = PredType.STRESS_POINT   # node or edge (A2.4)
    target_ref: str | None = None      # target-surface for an edge (transition); None for a node (single-anchor: surface_id=SOURCE)
    vuln_class: str | None = None      # vulnerability-class (CWE-closed-set; the boundary enforces)
    mechanism: str = ""                # exploit-mechanism (empty → rejected at the boundary)
    falsification_method: str = ""     # falsification-method (=testable-signal; empty → reject)
    measurement_category: MeasurementCategory | None = None  # A2.3 THREE-WAY: 1=now / 2=pending-detector
    pending_detector: str | None = None    # named future-detector for cat-2
    source_lens: str | None = None     # provenance (which lens found it — REQUIRED for #Ç4 per-lens)
    note: str = ""                    # free note for transparency (optional)


# ---------------------------------------------------------------------------
# NOTEBOOK — empty container + leak-proof access
# ---------------------------------------------------------------------------
# Its own OUTPUT-store (NOT the Prozessfall DB — that is READ-ONLY and input). When the AI arm
# arrives it is written here; empty for now. Repo-relative, portable.
DEFTER_YOLU_DEFAULT = "ai_kolu/ongoru_defteri.jsonl"


class OngoruDefteri:
    """
    Prediction-notebook. Starts EMPTY (no AI arm → no filling).

    LEAK-PROOFNESS CONTRACT (İ7): the ONLY legitimate access for routing to the user is
    `user_visible()`; HELD_OUT records are NOT RETURNED by any user-facing query.
    `held_out()` is only for EVALUATION (control-group reading), never routed to a surface.
    `route_to_user()` raises an ERROR if it tries to route a held_out (code-level barrier).

    NOTE (to the production side, in the future): held_out ASSIGNMENT (what fraction, how) is a calibration
    decision and must be fixed BEFORE ANY user sees output — blind/deterministic
    (e.g. a fraction split by a pred_id hash), non-gameable. The schema does not enforce this; the principle is here.
    """

    def __init__(self, kayitlar: list[Ongoru] | None = None):
        self._kayitlar: list[Ongoru] = list(kayitlar or [])   # starts empty

    # --- write (future; the AI arm calls) ---
    def record(self, o: Ongoru) -> None:
        """Add a prediction to the notebook. (Used when the AI arm arrives; not called for now.)"""
        self._kayitlar.append(o)

    def promote_to_tip1(self, pred_id: str, realized_ts: str) -> None:
        """
        REALITY-triggered promotion (İ5): kernel-tier rose up → TYPE-1. Must be called ONLY from
        measured reality (NOT from engagement, İ9a). The criterion is in the detector (tier-crossing); here is only the record.
        Status + realization are updated together.
        """
        for o in self._kayitlar:
            if o.pred_id == pred_id:
                o.realization = Realization.GERCEKLESTI
                o.realized_ts = realized_ts
                o.status = LinkStatus.TIP_1
                return
        raise KeyError(f"no prediction: {pred_id}")

    def mark_lapsed(self, pred_id: str, lapsed_ts: str) -> None:
        """
        Horizon-exceeded (2026-07-16 decision): realization-horizon passed, no signal → LAPSED. NOT CURUDU
        (negative ≠ evidence). THE RECORD IS NOT DELETED — only a state-transition (permanent). Status stays TYPE-2 (does not
        enter the kernel). held-out-LAPSED = #Ç4's only quasi-clean negative.
        """
        for o in self._kayitlar:
            if o.pred_id == pred_id:
                o.realization = Realization.LAPSED
                o.realized_ts = lapsed_ts
                return
        raise KeyError(f"no prediction: {pred_id}")

    # --- leak-proof reading ---
    def user_visible(self) -> list[Ongoru]:
        """The ONLY legitimate query for routing to the user. HELD_OUT is never returned (İ7 leak-proofness)."""
        return [o for o in self._kayitlar if o.exposure is Exposure.HIGHLIGHTED]

    def held_out(self) -> list[Ongoru]:
        """Control-group — ONLY evaluation (#Ç4). NOT routed to a surface."""
        return [o for o in self._kayitlar if o.exposure is Exposure.HELD_OUT]

    def route_to_user(self, o: Ongoru) -> Ongoru:
        """Code-level barrier: routing a held_out record is FORBIDDEN → error."""
        if o.exposure is Exposure.HELD_OUT:
            raise PermissionError(
                f"LEAK VIOLATION: held_out prediction ({o.pred_id}) cannot be routed to the user (İ7)."
            )
        return o

    def pending(self) -> list[Ongoru]:
        return [o for o in self._kayitlar if o.realization is Realization.BEKLIYOR]

    def pending_detector_queue(self) -> list[Ongoru]:
        """
        Category-2 VIEW (A2.5): predictions bound to a detector that is not-yet-built.
        NOT a separate store — a query over the notebook (single-source-of-truth). Tested once that detector is built.
        """
        return [o for o in self._kayitlar
                if o.measurement_category is MeasurementCategory.PENDING_DETECTOR]

    def __len__(self) -> int:
        return len(self._kayitlar)

    # --- #Ç4: self-fulfilling coefficient ---
    def confirmation_gap(self) -> dict:
        """
        #Ç4 — self-fulfilling coefficient. ASYMMETRIC (2026-07-16 clarification), NOT a symmetric-difference:
          • HELD_OUT = GOLD-STANDARD BASE (clean-reference). Not shown to the user → NO attention-effect
            → pure reality. held_out realization-rate = the true base-rate. held_out-LAPSED is also a clean negative.
          • HIGHLIGHTED = DEVIATION against the base (NOT the reference). highlighted-rate is a MIX of attention+skill;
            highlighted-LAPSED is AMBIGUOUS (either wrong or didn't draw attention) → clean-skill can't be read alone.
          • excess = highlighted_rate − held_out_baseline (≥0 = self-fulfilling inflation). The base is held_out;
            how much highlighted rises ABOVE it. IF IT WIDENS, pull autonomy back (İ7/İ8). LONGITUDINAL.
        On an empty notebook returns None (no data — honest). (Note: to turn held_out into SKILL you also
        need the NON-predicted surface base-rate — not in the notebook, in the surface-universe; a #Ç4 refinement.)
        """
        def _rate(grup: list[Ongoru]):
            # decided = GERCEKLESTI + CURUDU + LAPSED. BEKLIYOR does NOT ENTER the denominator (#Ç3 asymmetry:
            # pending ≠ failed → precision shouldn't inflate/deflate).
            karar = [o for o in grup if o.realization in
                     (Realization.GERCEKLESTI, Realization.CURUDU, Realization.LAPSED)]
            if not karar:
                return None, 0
            hit = sum(1 for o in karar if o.realization is Realization.GERCEKLESTI)
            return hit / len(karar), len(karar)

        baseline, ho_n = _rate(self.held_out())      # GOLD-STANDARD base
        hi_rate, hi_n = _rate(self.user_visible())   # measured against the base
        excess = (hi_rate - baseline) if (hi_rate is not None and baseline is not None) else None
        return {
            "held_out_baseline": baseline, "held_out_n": ho_n,     # clean-reference
            "highlighted_rate": hi_rate, "highlighted_n": hi_n,    # deviation-measured (mix)
            "excess": excess,   # highlighted − baseline; ≥0 self-fulfilling inflation
            "not": ("veri yok — #Ç4 masada çözülmez, defter dolunca okunur"
                    if excess is None else "excess>0 açılıyorsa self-fulfilling → otonomiyi geri çek"),
        }

    # --- persistence (its own store; NOT to Prozessfall) ---
    def save(self, path: str = DEFTER_YOLU_DEFAULT) -> None:
        with open(path, "w", encoding="utf-8") as f:
            for o in self._kayitlar:
                d = asdict(o)
                d["direction"] = o.direction.value
                d["exposure"] = o.exposure.value
                d["status"] = o.status.value
                d["realization"] = o.realization.value
                d["pred_type"] = o.pred_type.value
                d["measurement_category"] = o.measurement_category.value if o.measurement_category else None
                f.write(json.dumps(d, ensure_ascii=False) + "\n")

    @classmethod
    def load(cls, path: str = DEFTER_YOLU_DEFAULT) -> "OngoruDefteri":
        kayitlar: list[Ongoru] = []
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    d = json.loads(line)
                    kayitlar.append(Ongoru(
                        pred_id=d["pred_id"], surface_id=d["surface_id"],
                        direction=Direction(d["direction"]), content=d["content"],
                        created_ts=d["created_ts"], exposure=Exposure(d["exposure"]),
                        status=LinkStatus(d["status"]), realization=Realization(d["realization"]),
                        realized_ts=d.get("realized_ts"),
                        horizon_days=d.get("horizon_days"), tier_at_creation=d.get("tier_at_creation"),
                        pred_type=PredType(d.get("pred_type", "stress_point")),
                        target_ref=d.get("target_ref"), vuln_class=d.get("vuln_class"),
                        mechanism=d.get("mechanism", ""), falsification_method=d.get("falsification_method", ""),
                        measurement_category=(MeasurementCategory(d["measurement_category"])
                                              if d.get("measurement_category") else None),
                        pending_detector=d.get("pending_detector"), source_lens=d.get("source_lens"),
                        note=d.get("note", ""),
                    ))
        except FileNotFoundError:
            pass   # empty notebook — if no file there are no predictions yet (expected first-state)
        return cls(kayitlar)
