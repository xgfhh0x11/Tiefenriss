"""
test_a1.py — A1 (notebook-filling + realization-detector) synthetic regression.

Run: python3 -m ai_kolu.test_a1
All SYNTHETIC + in-memory → the production notebook stays EMPTY. Does not touch the kernel/DB.
"""
from .ongoru_defteri import OngoruDefteri, Direction, Exposure, Realization, LinkStatus
from .dolum import assign_exposure, record_prediction
from .realization_detector import detect
from . import defter_config as cfg


def test_exposure_deterministik_ve_surface_birim():
    # same surface → same exposure (multiple calls), reproducible
    e1 = assign_exposure("CWE-416×linux:linux_kernel")
    e2 = assign_exposure("CWE-416×linux:linux_kernel")
    assert e1 is e2, "aynı surface farklı exposure verdi (deterministik değil)"
    assert e1 in (Exposure.HIGHLIGHTED, Exposure.HELD_OUT)


def test_exposure_fraction_yaklasik_15():
    ids = [f"surf-{i}" for i in range(5000)]
    held = sum(1 for s in ids if assign_exposure(s) is Exposure.HELD_OUT)
    frac = held / len(ids)
    assert 0.13 <= frac <= 0.17, f"held-out kesri {frac:.3f} beklenen ~{cfg.HELD_OUT_FRACTION}"
    return frac


def test_ayni_surface_ayni_exposure_dolum():
    d = OngoruDefteri()
    o1 = record_prediction(d, "S1", Direction.ILERI, "path-a", "2026-01-01", "atla", pred_id="p1")
    o2 = record_prediction(d, "S1", Direction.GERI, "path-b", "2026-01-05", "taktik", pred_id="p2")
    assert o1.exposure is o2.exposure, "aynı surface'in iki öngörüsü farklı exposure aldı (birim≠surface)"
    assert o1.horizon_days == cfg.HORIZON_DAYS_BY_DIRECTION["ileri"]
    assert o1.tier_at_creation == "atla" and o2.tier_at_creation == "taktik"
    assert o1.status is LinkStatus.TIP_2 and o1.realization is Realization.BEKLIYOR


def test_detect_gerceklesme_tier_yukari():
    d = OngoruDefteri()
    record_prediction(d, "S1", Direction.ILERI, "x", "2026-01-01", "atla", pred_id="p1")
    rep = detect(d, {"S1": "taktik"}, "2026-02-01")          # taktik > atla → realized
    assert rep["promoted"] == 1, rep
    o = d._kayitlar[0]
    assert o.realization is Realization.GERCEKLESTI and o.status is LinkStatus.TIP_1
    assert o.realized_ts == "2026-02-01"


def test_detect_bekliyor_ufuk_ici():
    d = OngoruDefteri()
    record_prediction(d, "S2", Direction.ILERI, "x", "2026-01-01", "atla", pred_id="p2")
    rep = detect(d, {"S2": "atla"}, "2026-02-01")            # no movement, within horizon → wait
    assert rep["still_pending"] == 1 and rep["promoted"] == 0 and rep["lapsed"] == 0, rep
    assert d._kayitlar[0].realization is Realization.BEKLIYOR


def test_detect_lapse_ufuk_asildi():
    d = OngoruDefteri()
    record_prediction(d, "S3", Direction.ILERI, "x", "2026-01-01", "atla", pred_id="p3")  # horizon 180
    rep = detect(d, {"S3": "atla"}, "2026-08-01")            # ~212 days > 180, no movement → LAPSED
    assert rep["lapsed"] == 1, rep
    o = d._kayitlar[0]
    assert o.realization is Realization.LAPSED and o.status is LinkStatus.TIP_2  # stays type-2 (does not enter the kernel)


def test_detect_olculemez():
    d = OngoruDefteri()
    record_prediction(d, "S4", Direction.ILERI, "x", "2026-01-01", "atla", pred_id="p4")
    rep = detect(d, {}, "2026-02-01")                        # surface not in pipeline, within horizon → unmeasurable
    assert rep["unmeasurable"] == 1 and rep["still_pending"] == 0, rep
    assert d._kayitlar[0].realization is Realization.BEKLIYOR


def main():
    frac = None
    tests = [
        test_exposure_deterministik_ve_surface_birim,
        test_exposure_fraction_yaklasik_15,
        test_ayni_surface_ayni_exposure_dolum,
        test_detect_gerceklesme_tier_yukari,
        test_detect_bekliyor_ufuk_ici,
        test_detect_lapse_ufuk_asildi,
        test_detect_olculemez,
    ]
    print("=" * 70)
    print("A1 SYNTHETIC REGRESSION (notebook-filling + realization-detector)")
    print("=" * 70)
    for t in tests:
        r = t()
        if t is test_exposure_fraction_yaklasik_15:
            frac = r
        print(f"  ✓  {t.__name__}" + (f"  (held-out fraction={frac:.3f})" if frac and t is test_exposure_fraction_yaklasik_15 else ""))
    print("=" * 70)
    print(f"ALL A1 TESTS PASSED ({len(tests)}/{len(tests)}) — filling + detector correct.")
    print("Production notebook EMPTY (synthetic+in-memory). Kernel/DB untouched.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
