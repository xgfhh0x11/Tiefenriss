"""
test_pass2.py — A2 Pass-2: REAL operator + reality-gate + LABEL-HONESTY. Run: python3 -m ai_kolu.test_pass2

The Pass-1 pipeline was operator-agnostic; Pass-2 attaches the real Claude operator (llm_operator).
This test is DETERMINISTIC: operator-cognition = Fable-5 (this session) over REAL surfaces,
recorded into a RecordedBackend fixture (reproducibility). No LIVE call, does not touch the DB.

Three evaluation questions (researcher):
  Q1 does the pipeline carry the operator CLEANLY → free-JSON → Candidate → emit → assembly, type-flow, no crash.
  Q2 does label-honesty hold (CEILING)   → at a ceiling-surface an honest operator does NOT PLACE cat-1 (cat-2/none);
                                            a lie-cat-1 (ceiling) is caught in the BOUNDARY-guard.
  Q3 does the reality-gate catch speculation → structural-fakeness (none/outside-closed-set/ceiling) IS CAUGHT;
                                            BUT a semantic-wrong-label (philosophy→tier_crossing, non-ceiling)
                                            PASSES — the boundary is necessary-but-NOT-sufficient; #Ç4 downstream catches it.
"""
from .ongoru_defteri import OngoruDefteri, PredType
from .a2_types import Candidate, SignalKind
from .ongoru_defteri import Direction
from .boundary import admit, CEILING_TIER
from .yayim import emit_batch
from .montaj import assemble, weakest_atom
from .llm_operator import SurfaceContext, RecordedBackend, run_operator

# ── REAL surfaces (live-measurement 2026-07-18, adapter_bridge) ──────────────
CEIL = SurfaceContext(                       # CEILING: tier-crossing dead
    surface_id="CWE-125×linux:linux_kernel", cwe="CWE-125", vp="linux:linux_kernel",
    tier="stratejik", n_members=37, day_span="2026-04-22..2026-05-06",
    n_places=1, places_sample=["linux:linux_kernel"])
TAK = SurfaceContext(                         # NON-CEILING: tier-crossing live, CWE in-set
    surface_id="CWE-77×wavlink:wl-nu516u1_firmware", cwe="CWE-77", vp="wavlink:wl-nu516u1_firmware",
    tier="taktik", n_members=9, day_span="2026-04-20..2026-05-04",
    n_places=1, places_sample=["wavlink:wl-nu516u1_firmware"])

# ── RECORDED OPERATOR-COGNITION (Fable-5, this session; HONEST multi-lens output) ──
# At the ceiling-surface the teknik-lens produces cat-2 (NOT tier-crossing — HONESTY-CONTRACT ceiling-rule);
# the felsefi-lens can't name a signal and says none (honest self-reject). Non-ceiling: teknik produces cat-1.
RECORDED = {
    (CEIL.surface_id, "teknik"): """[
      {"pred_type":"stress_point","vuln_class":"CWE-125",
       "mechanism":"kernel slab yolunda OOB-read → komşu-obje ifşası → KASLR/heap-düzen sızıntı primitive'i",
       "signal_kind":"future_detector","detector_name":"subsystem-leak-detector","signal_horizon_days":540,
       "falsification_method":"belirli bir kernel-subsystem'de OOB-read'in bilgi-sızıntısı zincirine girdiği CVE/exploit belirir"},
      {"pred_type":"transition","target_ref":"CWE-787×linux:linux_kernel","vuln_class":"CWE-125",
       "mechanism":"info-leak → heap-groom → OOB-write pivotu (leak ile write'ı aynı zincire bağla)",
       "signal_kind":"future_detector","detector_name":"colocation-detector","signal_horizon_days":540,
       "falsification_method":"aynı-commit/exploit-zincirinde ilişkili write CVE (colocation)"}
    ]""",
    (CEIL.surface_id, "felsefi"): """[
      {"pred_type":"stress_point","vuln_class":"CWE-125",
       "mechanism":"OOB-read, performans-güdümlü sınır-eleme ile bellek-güvenliği arasındaki kavramsal gerilimi yansıtıyor",
       "signal_kind":"none","falsification_method":"kavramsal-gerilim; ölçülebilir bir gerçeklik-sinyaline indirgenemiyor"}
    ]""",
    (TAK.surface_id, "teknik"): """[
      {"pred_type":"stress_point","vuln_class":"CWE-77",
       "mechanism":"router firmware yönetim-arayüzünde komut-enjeksiyonu: sanitize-edilmemiş parametre shell'e geçer → RCE primitive",
       "signal_kind":"tier_crossing",
       "falsification_method":"bu surface'in çekirdek-tier'ı taktik'ten yukarı aşar (yeni komut-enjeksiyon CVE'leri birikir)"}
    ]""",
    (TAK.surface_id, "tarihsel"): """[
      {"pred_type":"stress_point","vuln_class":"CWE-77",
       "mechanism":"SOHO-router ailelerinde komut-enjeksiyonu tarihsel olarak diagnostik/güncelleme uçlarında kümelenir → aynı desen bu üründe",
       "signal_kind":"future_detector","detector_name":"soho-firmware-endpoint-detector","signal_horizon_days":540,
       "falsification_method":"bu üründe diagnostik/güncelleme uç-noktasında yeni komut-enjeksiyon CVE'si belirir"}
    ]""",
}


def _probe(**kw) -> Candidate:
    base = dict(direction=Direction.ILERI, pred_type=PredType.STRESS_POINT, source_lens="probe")
    base.update(kw)
    return Candidate(**base)


def run():
    results = []
    def ok(name): results.append(name)

    backend = RecordedBackend(RECORDED)

    # ── HONEST FLOW: real operator → pipeline ──
    ceil_cands = run_operator(CEIL, backend, "stratejik")   # 6 lenses; 4 return empty
    tak_cands = run_operator(TAK, backend, "taktik")        # 2 lenses

    d1 = OngoruDefteri()
    rep_c = emit_batch(d1, ceil_cands, created_ts="2026-07-18")
    d2 = OngoruDefteri()
    rep_t = emit_batch(d2, tak_cands, created_ts="2026-07-18")

    # Q1 — pipeline carries cleanly: free-JSON → typed Candidate → in the notebook, no crash
    assert len(ceil_cands) == 3 and len(tak_cands) == 2, (len(ceil_cands), len(tak_cands))
    assert rep_c["counts"]["admitted"] >= 1 and rep_t["counts"]["admitted"] >= 1
    ok(f"Q1 boru operatörü temiz-taşıyor (tavan {rep_c['counts']} · non-ceiling {rep_t['counts']})")

    # Q2a — CEILING honesty: at the ceiling-surface the operator did NOT PRODUCE cat-1 (all cat-2), none rejected
    ceil_admitted = [o for o in d1._kayitlar]
    assert all(o.measurement_category and o.measurement_category.value == "2" for o in ceil_admitted), \
        "tavan-surface'te kat-1 sızdı (dürüstlük ihlali)"
    assert rep_c["counts"]["cat1"] == 0 and rep_c["counts"]["cat2"] == 2, rep_c["counts"]
    felsefi_red = [r for r in rep_c["red_log"] if r["source_lens"] == "felsefi"]
    assert len(felsefi_red) == 1 and felsefi_red[0]["empty_field"] == "signal_kind", felsefi_red
    ok("Q2a tavan-dürüstlüğü: operatör kat-1 KOYMADI (2 kat-2), felsefe-none SINIRDA reddedildi")

    # non-ceiling: cat-1 works HONESTLY (the surface can rise up)
    assert rep_t["counts"]["cat1"] == 1 and rep_t["counts"]["cat2"] == 1, rep_t["counts"]
    ok("non-ceiling: dürüst kat-1 çalışıyor (taktik yukarı-aşabilir) + kat-2")

    # Q2b — CEILING-GUARD (structural backstop): a lie-cat-1 (ceiling) is caught at the BOUNDARY
    p_ceil_lie = _probe(key="P-ceil-lie", surface_id=CEIL.surface_id, vuln_class="CWE-125",
                        mechanism="var", signal_kind=SignalKind.TIER_CROSSING,
                        falsification_method="tier yükselir", tier_at_creation=CEILING_TIER)
    r = admit(p_ceil_lie)
    assert not r.admitted and r.empty_field == "signal_kind" and "tavan" in r.reason, r
    ok("Q2b tavan-guard: yalan-kat-1 (tavan-surface tier_crossing) SINIRDA yakalandı → kat-2'ye zorlar")

    # Q3 — THE BOUNDARY'S LIMIT (honest finding): a semantic-wrong-label PASSES, only structural is caught
    #   (i) structurally-honest philosophy (none) → caught
    p_philo_honest = _probe(key="P-philo-honest", surface_id=TAK.surface_id, vuln_class="CWE-125",
                            mechanism="kurumsal-ihmali yansıtan derin sezgi", signal_kind=SignalKind.NONE,
                            falsification_method="sezgisel olarak açık ama ölçülebilir sinyal yok",
                            tier_at_creation="taktik")
    #   (ii) semantically-lying philosophy: same empty-intuition but tier_crossing + non-ceiling → structurally-valid → PASSES
    p_philo_lie = _probe(key="P-philo-lie", surface_id=TAK.surface_id, vuln_class="CWE-125",
                         mechanism="kurumsal-ihmali yansıtan derin sezgi", signal_kind=SignalKind.TIER_CROSSING,
                         falsification_method="tier yükselir", tier_at_creation="taktik")
    rh, rl = admit(p_philo_honest), admit(p_philo_lie)
    assert not rh.admitted and rh.empty_field == "signal_kind", rh
    assert rl.admitted, "anlamsal-yalan yakalanmalıydı-SANILDI ama sınır anlamı görmez (beklenen limit)"
    ok("Q3 sınır-limiti: yapısal-sahte (none) yakalanır; anlamsal-yalan (felsefe→tier_crossing) GEÇER → #Ç4-yükü")

    # assembly: a path from the ceiling-surface's 2 cat-2 atoms (node+transition), weakest-atom
    amap = rep_c["admitted_map"]
    reg = assemble([{"path_id": "P-tavan", "direction": "ileri", "atom_keys": list(amap)}], amap)
    w = weakest_atom(reg._paths[0], d1)
    assert w and w["realization"] == "bekliyor", w
    ok("montaj: tavan-path kuruldu (kat-2 atomlar bekliyor); en-zayıf-atom doğru")

    return results


def main():
    print("=" * 74)
    print("A2 PASS-2: REAL operator (Fable-5, recorded) + reality-gate + LABEL-HONESTY")
    print("=" * 74)
    for name in run():
        print(f"  ✓  {name}")
    print("=" * 74)
    print("PASS-2 PASSED — the operator flows cleanly through the pipeline; ceiling-honesty structuralized with the guard;")
    print("that a semantic-lie passes the boundary (only #Ç4 catches it) was HONESTLY proven. Production notebook EMPTY.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
