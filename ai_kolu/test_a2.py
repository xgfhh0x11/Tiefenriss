"""
test_a2.py — A2 Pass-1 ADVERSARIAL pipeline regression. Run: python3 -m ai_kolu.test_a2

Proves the pipeline CORRECTLY passes/rejects every boundary-case (admit + each reject-branch).
ANTI-GREEN-DECEPTIVE: the reject-count must match the expected — if a reject leaks (easy-pass) the test CRASHES.
Synthetic + in-memory → the production notebook is EMPTY. Does not touch the kernel/DB.
"""
from .ongoru_defteri import OngoruDefteri, Exposure, Realization, PredType
from .dolum import assign_exposure
from .yayim import emit_batch
from .montaj import assemble, weakest_atom
from .stub_operator import build_battery


def _find_held_out_sid():
    i = 0
    while i < 10000:
        sid = f"HELDOUT-PROBE-{i}"
        if assign_exposure(sid) is Exposure.HELD_OUT:
            return sid
        i += 1
    raise RuntimeError("held-out surface not found (f=0?)")


def run():
    results = []

    def ok(name):
        results.append(name)

    held = _find_held_out_sid()
    items, path_specs = build_battery(held)
    cands = [it["cand"] for it in items]

    defter = OngoruDefteri()
    rep = emit_batch(defter, cands, created_ts="2026-07-18")
    amap, red_log = rep["admitted_map"], rep["red_log"]
    red_by_key = {r["key"]: r for r in red_log}

    # 1) is each case as expected (admit→in-notebook+category / reject→reject-log+field)
    exp_admit = exp_reject = 0
    for it in items:
        k, cand = it["cand"].key, it["cand"]
        if it["admit"]:
            exp_admit += 1
            assert k in amap, f"{k} admit bekleniyordu, olmadı ({it['note']})"
            o = next(o for o in defter._kayitlar if o.pred_id == k)
            assert o.measurement_category and o.measurement_category.value == it["cat"], \
                f"{k} kategori {it['cat']} bekleniyordu, {o.measurement_category}"
        else:
            exp_reject += 1
            assert k not in amap, f"{k} RED bekleniyordu ama admit oldu — YEŞİL-ALDATICI ({it['note']})"
            assert k in red_by_key, f"{k} red-log'da yok"
            assert red_by_key[k]["empty_field"] == it["field"], \
                f"{k} red-alan {it['field']} bekleniyordu, {red_by_key[k]['empty_field']}"
    ok(f"her vaka doğru ({exp_admit} admit / {exp_reject} reject)")

    # 2) ANTI-GREEN-DECEPTIVE: counts exact
    assert rep["counts"]["admitted"] == exp_admit and rep["counts"]["rejected"] == exp_reject, rep["counts"]
    assert exp_reject >= 8, "adversarial battery yeterince red-vakası içermeli"
    ok(f"anti-yeşil-aldatıcı: {exp_reject} red gerçekten oldu")

    # 3) A4 (novel-but-testable) PASSED, R8 (technical-but-untestable) REJECTED → the central principle
    assert "A4" in amap and "R8" not in amap, "yanlışlanabilirlik≠gelenekssellik ilkesi ihlal"
    ok("sınır: novel-sınanabilir geçer, teknik-sınanamaz reddedilir")

    # 4) single-anchor: transition(A3) anchored to the SOURCE surface, target separate
    a3 = next(o for o in defter._kayitlar if o.pred_id == "A3")
    assert a3.pred_type is PredType.TRANSITION and a3.surface_id == "CWE-200×linux:linux_kernel"
    assert a3.target_ref == "CWE-787×linux:linux_kernel", "tek-çapa bozuk (hedef çapa olmuş)"
    ok("tek-çapa: geçiş kaynak-surface'e çapalı (çift-saymaz)")

    # 5) exposure-blind: the held-out atom was written but OUTSIDE user_visible
    assert "A5" in amap
    a5 = next(o for o in defter._kayitlar if o.pred_id == "A5")
    assert a5.exposure is Exposure.HELD_OUT
    assert "A5" not in [o.pred_id for o in defter.user_visible()], "held-out SIZDI (user_visible)"
    ok("exposure-kör: held-out yazıldı, sunumda gizli (sızmaz)")

    # 6) pending-detector view: cat-2 (A2) in the queue, cat-1 (A1) not
    pdq = [o.pred_id for o in defter.pending_detector_queue()]
    assert "A2" in pdq and "A1" not in pdq, pdq
    ok("pending-detector kuyruğu: kat-2 içeride, kat-1 dışarıda")

    # 7) assembly: complete vs incomplete path; the weakest-atom counts the TRANSITION
    reg = assemble(path_specs, amap)
    komple = next(p for p in reg._paths if p.path_id == "P-komple")
    eksik = next(p for p in reg._paths if p.path_id == "P-eksik")
    assert komple.complete and not eksik.complete and eksik.missing_atom_keys == ["R1"]
    # realize the nodes (A1,A4), let the transition(A3) stay BEKLIYOR → weakest = A3 (edge)
    defter.promote_to_tip1("A1", "2026-08-01")
    defter.promote_to_tip1("A4", "2026-08-01")
    w = weakest_atom(komple, defter)
    assert w and w["pred_id"] == "A3" and w["pred_type"] == "transition", \
        f"en-zayıf-atom geçişi saymadı: {w}"
    ok("montaj: eksik-path elendi; en-zayıf-atom GEÇİŞİ sayıyor (A3)")

    # 8) A1-compatibility: save/load round-trip preserves the new fields
    import os
    p = os.path.join(os.environ.get("TMPDIR", "/tmp"), "test_a2_defter.jsonl")
    defter.save(p)
    d2 = OngoruDefteri.load(p)
    a2b = next(o for o in d2._kayitlar if o.pred_id == "A2")
    a3b = next(o for o in d2._kayitlar if o.pred_id == "A3")
    assert a2b.measurement_category and a2b.measurement_category.value == "2" and a2b.pending_detector == "colocation-detector"
    assert a3b.pred_type is PredType.TRANSITION and a3b.target_ref == "CWE-787×linux:linux_kernel"
    os.remove(p)
    ok("A1-uyumu: save/load yeni A2 alanlarını korur")

    return results


def main():
    print("=" * 74)
    print("A2 PASS-1 ADVERSARIAL PIPELINE REGRESSION (produce→filter→assemble→emit, STUB)")
    print("=" * 74)
    for name in run():
        print(f"  ✓  {name}")
    print("=" * 74)
    print("ALL A2 PASS-1 TESTS PASSED — the pipeline passes boundary-cases correctly (NOT stub-easy).")
    print("Production notebook EMPTY · NO LLM (stub) · kernel/DB untouched.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
