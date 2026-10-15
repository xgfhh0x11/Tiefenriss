"""
test_pass1.py — Pass-1 deterministic architecture-validation (NO LLM/network).

Checks (one case per discipline-path):
  T1  schema/status-typing        — merge produces records, every field an Attribute (carries status)
  T2  OPEN ≠ null + BARRIER       — CVE-B cwe stays OPEN; measured() raises DisciplineError
  T3  join-enrichment (promotion) — CVE-A cwe OPEN(kernel)→MEASURED(nvd); history carries the promotion
  T4  trust-order (conflict)      — CVE-A cwe = CWE-416 (NVD MEASURED beats heuristic DERIVED)
  T5  QUARANTINED does not leak    — exploit_likelihood measured() refused; is_quarantined() True
  T6  two-role separation          — SurfaceSource→PartialSurface, RealizationSource→RealizationEvent
  T7  refs first-class             — CVE-A refs MEASURED, CVE-B refs OPEN (0-refs not fabricated)
  T8  zone-routing                 — CVE-A/C reachable, CVE-B hardware
  T9  status-evolution (time-gate) — CVE-B cwe OPEN→MEASURED (backlog); history two-entries, measured() returns
  T10 anti-green (barrier is real) — discipline violations REALLY raise (no false-positive-green)
  T11 OPEN-stickiness (decision-b) — QUARANTINED does not override OPEN
  T12 aggregate()                  — subsystem-keyed SurfaceElement + CWE-distribution aggregate + interface first-class
"""
from __future__ import annotations

from .status import DisciplineError, Attribute, Status
from .record import MergedRecord, PartialSurface, RealizationEvent, SurfaceElement, SurfaceSource, RealizationSource, Zone
from .merge import merge
from .aggregate import aggregate
from .stub_source import (
    KernelGitStub, NvdStub, HeuristicStub, QuarantineStub, SyzbotStub, AdvisoryStub, T0,
)


def _build() -> dict[str, MergedRecord]:
    """Collect the surface-sources → merge → key(cve)→MergedRecord dict."""
    partials = []
    for source in (KernelGitStub(), NvdStub(), HeuristicStub(), QuarantineStub()):
        partials.extend(source.produce())
    records = merge(partials, when=T0)
    return {r.key: r for r in records}


def _realizations() -> list[RealizationEvent]:
    events = []
    for source in (SyzbotStub(), AdvisoryStub()):
        events.extend(source.produce())
    return events


def main() -> int:
    passed = 0
    failed = 0

    def check(cond: bool, label: str):
        nonlocal passed, failed
        if cond:
            passed += 1
            print(f"  ✓ {label}")
        else:
            failed += 1
            print(f"  ✗ {label}")

    S = _build()

    # --- T1 schema/status-typing ---
    check(set(S) == {"CVE-A", "CVE-B", "CVE-C", "CVE-D", "CVE-E"}, "T1 merge produced five MergedRecords")
    check(all(isinstance(a, Attribute) for a in S["CVE-A"].fields.values()),
          "T1 every field is an Attribute (carries status)")

    # --- T2 OPEN ≠ null + barrier ---
    b_cwe = S["CVE-B"].field("cwe")
    check(b_cwe.is_open() and b_cwe.value is None, "T2 CVE-B cwe OPEN (no NVD), value=None")
    caught = False
    try:
        b_cwe.measured()
    except DisciplineError:
        caught = True
    check(caught, "T2 measured() raised DisciplineError on OPEN (OPEN cannot be treated as measured)")

    # --- T3 join-enrichment (OPEN→MEASURED promotion + history) ---
    a_cwe = S["CVE-A"].field("cwe")
    check(a_cwe.is_measured(), "T3 CVE-A cwe MEASURED after join (was OPEN in kernel, NVD filled)")
    promo_trail = any("filled" in t.reason for t in a_cwe.history)
    check(promo_trail, "T3 history carries the join-promotion (OPEN→filled) auditably")

    # --- T4 trust-order (three-way conflict) ---
    check(a_cwe.measured() == "CWE-416",
          "T4 on conflict NVD-MEASURED (CWE-416) won, heuristic-DERIVED(CWE-119) lost")

    # --- T5 QUARANTINED does not leak ---
    b_exp = S["CVE-B"].field("exploit_likelihood")
    check(b_exp is not None and b_exp.is_quarantined(), "T5 exploit_likelihood QUARANTINED")
    q_caught = False
    try:
        b_exp.measured()
    except DisciplineError:
        q_caught = True
    check(q_caught, "T5 QUARANTINED value did not leak via measured() (barrier refused)")
    check(b_exp.quarantined_value() == 0.9, "T5 knowingly-suspect access (quarantined_value) works")

    # --- T6 two-role separation ---
    check(isinstance(KernelGitStub(), SurfaceSource) and isinstance(SyzbotStub(), RealizationSource),
          "T6 stubs implement the right role (Surface vs Realization Protocol)")
    events = _realizations()
    check(all(isinstance(e, RealizationEvent) for e in events) and
          not any(isinstance(e, (MergedRecord, PartialSurface)) for e in events),
          "T6 realization events are NOT records/surfaces (separate role, separate downstream)")
    a_real = [e for e in events if e.surface_key == "CVE-A"]
    check(len(a_real) == 1 and a_real[0].status is Status.QUARANTINED,
          "T6 CVE-A realization QUARANTINED (syzbot audit-bias — no auto-promotion to tip-1)")

    # --- T7 refs first-class (blind-spot lesson) ---
    check(S["CVE-A"].refs.is_measured(), "T7 CVE-A refs MEASURED (advisory-link captured)")
    check(S["CVE-B"].refs.is_open(), "T7 CVE-B refs OPEN (0-refs not fabricated — census blind-spot closed)")
    check(len(S["CVE-C"].refs.measured()) == 2, "T7 CVE-C dual-ref (guest-host chain) preserved")

    # --- T8 zone-routing ---
    check(S["CVE-A"].zone.measured() is Zone.REACHABLE and S["CVE-C"].zone.measured() is Zone.REACHABLE,
          "T8 CVE-A/C zone=REACHABLE (machine-#Ç4)")
    check(S["CVE-B"].zone.measured() is Zone.HARDWARE, "T8 CVE-B zone=HARDWARE (syzbot blind → human-arm)")
    check(not any(e.surface_key == "CVE-B" for e in events),
          "T8 no realization produced for CVE-B (hardware) (cold-zone, deliberate gap)")

    # --- T9 status-evolution (the data-layer form of the time-gate) ---
    b_cwe.evolve(Status.MEASURED, "CWE-787", "nvd-backlog", "2026-09-01", "backlog filled")
    check(b_cwe.measured() == "CWE-787" and len(b_cwe.history) == 2,
          "T9 CVE-B cwe OPEN→MEASURED evolved, history two-entries (not deleted, transition written)")
    check(b_cwe.history[0].status is Status.OPEN and b_cwe.history[1].status is Status.MEASURED,
          "T9 history trail has the right OPEN→MEASURED order (auditable time-gate)")

    # --- T10 anti-green: do the barriers really catch (no false-positive-green) ---
    derived = Attribute.of_derived("CWE-119", "heuristic", T0)
    d_caught = False
    try:
        derived.measured()      # DERIVED is also not-MEASURED → barrier must refuse
    except DisciplineError:
        d_caught = True
    check(d_caught, "T10 a DERIVED value also cannot pass the measured() barrier (marked≠measured)")
    wrong_method = False
    try:
        S["CVE-A"].field("cwe").quarantined_value()   # quarantined_value() on MEASURED is wrong-method → error
    except DisciplineError:
        wrong_method = True
    check(wrong_method, "T10 quarantined_value() refused on a MEASURED field (wrong-method barrier)")

    # --- T11 OPEN-stickiness (decision-b): QUARANTINED does NOT override OPEN ---
    e_cwe = S["CVE-E"].field("cwe")   # kernel OPEN + quarantine-stub QUARANTINED(CWE-999)
    check(e_cwe.is_open(), "T11 CVE-E cwe STAYED OPEN (QUARANTINED-suspect did not override deliberate abstention)")
    check(e_cwe.value is None, "T11 after OPEN-stickiness value is None (CWE-999 did not leak)")

    # --- T12 aggregate(): subsystem-keyed SurfaceElement + CWE-distribution + interface first-class ---
    # (fresh _build() — isolated from T9's CVE-B mutation: aggregation must see the original join statuses)
    elements = aggregate(list(_build().values()), when=T0)
    ES = {e.subsystem: e for e in elements}
    check(set(ES) == {"net/ipv4", "drivers/gpu/drm", "arch/x86/kvm"},
          "T12 elements are subsystem-keyed (CWE is NOT the key)")

    net = ES["net/ipv4"]   # CVE-A(416), CVE-D(125), CVE-E(open) → 3 CVEs
    check(net.cve_count == 3 and set(net.cve_keys) == {"CVE-A", "CVE-D", "CVE-E"},
          "T12 net/ipv4 aggregated three CVEs (OPEN-CVE included, NOT LOST)")
    d = net.cwe.measured()   # aggregate MEASURED (coverage>0)
    check(d["distribution"] == {"CWE-416": 1, "CWE-125": 1} and d["open_n"] == 1 and d["measured_n"] == 2,
          "T12 CWE-distribution over measured subset {416:1,125:1}, open=1 (not fabricated)")
    check(abs(d["coverage"] - 2/3) < 1e-3, "T12 coverage≈0.667 (OPEN-fraction carried honestly → v0 weights uncertainty)")

    gpu = ES["drivers/gpu/drm"]   # CVE-B alone, cwe OPEN (no NVD)
    check(gpu.cwe.is_open(), "T12 drivers/gpu/drm element-CWE OPEN (mostly-open element → v0-uncertain, honest)")

    kvm = ES["arch/x86/kvm"]   # CVE-C, interface subsystem
    check(kvm.is_interface, "T12 arch/x86/kvm SEAM element (is_interface=True) — T4 guest-host interface first-class")
    check(not net.is_interface, "T12 net/ipv4 not a seam (is_interface=False) — distinction correct")
    check(kvm.zone.measured() is Zone.REACHABLE, "T12 kvm element-zone REACHABLE (machine-#Ç4)")

    # --- T13 external_refs() extraction (Pass-2b seam/cross-project logic) ---
    from .kaynaklar.refs import external_refs
    c_refs = S["CVE-C"].refs.measured()   # ["https://xenbits/...", "https://lore.kernel.org/kvm"]
    ext = external_refs(c_refs)
    check(ext == ["https://xenbits/advisory/XSA-999"],
          "T13 external_refs picks the cross-project ref (xenbits), drops the kernel.org one")
    check(external_refs(S["CVE-A"].refs.measured()) == [],
          "T13 all-kernel.org refs → no external (empty, not fabricated)")

    print(f"\n  Pass-1: {passed} passed / {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
