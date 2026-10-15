"""
stub_operator.py — Pass-1 ADVERSARIAL stub (NOT an LLM). Its real value: throwing boundary-cases at the pipeline.

If it feeds easy ones the pipeline passes trivially (green-deceptive). This battery deliberately forces every reject-branch of the BOUNDARY
+ every critical admit-case (novel-but-testable, held-out, transition, cat-2). In Pass-2 the real
Claude operator takes its place; the pipeline stays the same.

build_battery(held_out_sid) → (candidates+expectation, path-specs).
"""
from __future__ import annotations

from .ongoru_defteri import Direction, PredType
from .a2_types import Candidate, SignalKind


def _c(**kw) -> Candidate:
    base = dict(direction=Direction.ILERI, pred_type=PredType.STRESS_POINT, tier_at_creation="atla")
    base.update(kw)
    return Candidate(**base)


def build_battery(held_out_sid: str):
    """held_out_sid: a known surface whose exposure falls to HELD_OUT (from a test probe)."""
    items = []

    def add(cand, admit, field="", cat=None, note=""):
        items.append({"cand": cand, "admit": admit, "field": field, "cat": cat, "note": note})

    # ── ADMIT cases ──
    add(_c(key="A1", surface_id="CWE-416×linux:linux_kernel", vuln_class="CWE-416",
           mechanism="slab UAF → tekrar-tahsis primitive", signal_kind=SignalKind.TIER_CROSSING,
           falsification_method="surface tier'ı atla→taktik+ aşar", source_lens="teknik"),
        True, cat="1", note="temiz kat-1 düğüm")

    add(_c(key="A2", surface_id="CWE-787×linux:linux_kernel", vuln_class="CWE-787",
           mechanism="OOB write → komşu-obje bozma", signal_kind=SignalKind.FUTURE_DETECTOR,
           detector_name="colocation-detector", signal_horizon_days=365,
           falsification_method="aynı-commit'te ilişkili CVE düzelir mi", source_lens="tarihsel"),
        True, cat="2", note="kat-2 SINIRLI (detector+ufuk) → pending-detector")

    add(_c(key="A3", pred_type=PredType.TRANSITION, target_ref="CWE-787×linux:linux_kernel",
           surface_id="CWE-200×linux:linux_kernel", vuln_class="CWE-200",
           mechanism="leak → KASLR kır → write hedefle", signal_kind=SignalKind.TIER_CROSSING,
           falsification_method="hedef surface tier'ı yükselir", source_lens="teknik"),
        True, cat="1", note="GEÇİŞ atomu (kenar) — kaynak-çapa, hedef ayrı")

    add(_c(key="A4", surface_id="CWE-362×linux:linux_kernel", vuln_class="CWE-362",
           mechanism="savunmacının 'imkansız' saydığı yarış-penceresi",
           signal_kind=SignalKind.TIER_CROSSING,
           falsification_method="race surface tier'ı yükselir", source_lens="psikolojik"),
        True, cat="1", note="NOVEL-ama-sınanabilir → GEÇMELİ (yanlışlanabilirlik, gelenekssellik değil)")

    add(_c(key="A5", surface_id=held_out_sid, vuln_class="CWE-416",
           mechanism="UAF held-out surface'te", signal_kind=SignalKind.TIER_CROSSING,
           falsification_method="tier yükselir", source_lens="teknik"),
        True, cat="1", note="HELD-OUT surface → yazılır ama user_visible DIŞI (exposure-kör)")

    # ── REJECT cases (each reject-branch) ──
    add(_c(key="R1", surface_id="s", vuln_class="CWE-611",   # XXE — NOT in the v0 set
           mechanism="xxe", signal_kind=SignalKind.TIER_CROSSING,
           falsification_method="x", source_lens="teknik"),
        False, field="vuln_class", note="CWE kapalı-küme dışı")

    add(_c(key="R2", surface_id="s", vuln_class="CWE-416",
           mechanism="var", signal_kind=SignalKind.NONE,
           falsification_method="kurumsal-ihmali yansıtıyor", source_lens="felsefi"),
        False, field="signal_kind", note="ölçüm-tanımsız = kat-3 felsefe")

    add(_c(key="R3", surface_id="s", vuln_class="CWE-416",
           mechanism="   ", signal_kind=SignalKind.TIER_CROSSING,
           falsification_method="x", source_lens="teknik"),
        False, field="mechanism", note="mekanizma boş")

    add(_c(key="R4", surface_id="s", vuln_class="CWE-787",
           mechanism="var", signal_kind=SignalKind.FUTURE_DETECTOR,
           detector_name="hayali-detector", signal_horizon_days=99999,   # unbounded horizon
           falsification_method="50 yılda 0-day düşerse", source_lens="tarihsel"),
        False, field="signal_horizon_days", note="kat-2 ufuk fizibilitesiz = gizli kat-3 (muhafız-a)")

    add(_c(key="R5", surface_id="s", vuln_class="CWE-787",
           mechanism="var", signal_kind=SignalKind.FUTURE_DETECTOR,
           detector_name=None, signal_horizon_days=365,   # no detector-name
           falsification_method="bir gün ölçülür", source_lens="tarihsel"),
        False, field="detector_name", note="kat-2 detector-adı yok = gizli kat-3")

    add(_c(key="R6", pred_type=PredType.TRANSITION, target_ref=None,   # transition but no target
           surface_id="s", vuln_class="CWE-200", mechanism="pivot",
           signal_kind=SignalKind.TIER_CROSSING, falsification_method="x", source_lens="teknik"),
        False, field="target_ref", note="geçiş hedef-ref yok")

    add(_c(key="R7", surface_id="s", vuln_class="CWE-416",
           mechanism="var", signal_kind=SignalKind.TIER_CROSSING,
           falsification_method="   ", source_lens="teknik"),
        False, field="falsification_method", note="yanlışlama-yöntemi boş")

    add(_c(key="R8", surface_id="s", vuln_class="CWE-416",   # technical+in-set but untestable
           mechanism="gerçek-görünen teknik anlatı", signal_kind=SignalKind.NONE,
           falsification_method="sezgisel olarak açık", source_lens="teknik"),
        False, field="signal_kind", note="TEKNİK-görünüm sınanamazsa KURTARMAZ (A4 ile eş: gelenekssellik≠yanlışlanabilirlik)")

    add(_c(key="R9", surface_id="s", vuln_class="CWE-416",   # boundary-fields FULLY valid (passes the boundary)
           mechanism="var", signal_kind=SignalKind.TIER_CROSSING,
           falsification_method="tier yükselir", source_lens="teknik",
           tier_at_creation=None),   # ...BUT NO tier-snapshot → realization-anchor unmeasurable → REJECTED at emission
        False, field="tier_at_creation",
        note="A-türü ölçüm-çapası: snapshot yok → REDDET (sessiz-atla-default kaldırıldı, İ9b)")

    # path-specs: one COMPLETE (node-transition-node, weakest-transition test), one INCOMPLETE (with a rejected atom)
    path_specs = [
        {"path_id": "P-komple", "direction": "ileri", "atom_keys": ["A1", "A3", "A4"]},
        {"path_id": "P-eksik", "direction": "ileri", "atom_keys": ["A1", "R1", "A4"]},  # R1 rejected → incomplete
    ]
    return items, path_specs
