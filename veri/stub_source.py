"""
stub_source.py — Pass-1 ADVERSARIAL stub sources (deterministic, NO LLM/network).

Purpose: validate the status-typed schema + join ARCHITECTURE before the real fetcher. Stubs are deliberately
ADVERSARIAL — each discipline-path is exercised by one case:
  CVE-A : cwe OPEN(kernel) ⋈ MEASURED(nvd) ⋈ DERIVED(heuristic)  → join-promotion + trust-order conflict
  CVE-B : cwe OPEN and NO-NVD → stays OPEN (OPEN≠null survivor) + refs OPEN (census 0-refs blind-spot)
          + a QUARANTINED field (exploit_likelihood) → must not leak
  CVE-C : dual-ref (guest-host chain) MEASURED + coordinated-advisory realization MEASURED
  CVE-D, CVE-E : net/ipv4 (same subsystem as CVE-A) → exercises aggregate() and OPEN-stickiness
Realization: syzbot(CVE-A, QUARANTINED, reachable) + advisory(CVE-C, MEASURED, reachable). CVE-B → no realization (hardware, syzbot blind).

Time is caller-supplied; the stub uses a fixed day-str (deterministic).
"""
from __future__ import annotations

from .status import Attribute, Status
from .record import PartialSurface, RealizationEvent, Zone


T0 = "2026-07-19"   # fixed stub timestamp (deterministic)


class KernelGitStub:
    """SurfaceSource — kernel-CVE-git-like: subsystem/commit MEASURED, cwe OPEN (kernel-CNA assigns no CWE)."""
    name = "kernel-git-stub"

    def produce(self):
        return [
            PartialSurface(key="CVE-A", domain="linux-kernel", source_name=self.name, fields={
                "subsystem": Attribute.of_measured("net/ipv4", self.name, T0, "from commit-path"),
                "commit": Attribute.of_measured("abc123", self.name, T0),
                "cwe": Attribute.of_open(self.name, T0, "kernel-CNA assigns no CWE"),
                "refs": Attribute.of_measured(["https://lore.kernel.org/x"], self.name, T0),
                "zone": Attribute.of_measured(Zone.REACHABLE, self.name, T0, "net → syscall-reachable"),
            }),
            PartialSurface(key="CVE-B", domain="linux-kernel", source_name=self.name, fields={
                "subsystem": Attribute.of_measured("drivers/gpu/drm", self.name, T0),
                "commit": Attribute.of_measured("def456", self.name, T0),
                "cwe": Attribute.of_open(self.name, T0, "kernel-CNA assigns no CWE"),
                # no refs → join OPEN-fills (census 0/450-refs blind-spot; no fabrication)
                "zone": Attribute.of_measured(Zone.HARDWARE, self.name, T0, "gpu → hardware-bound, syzbot blind"),
                # QUARANTINED field: measured but suspect (audit-bias) → must not leak downstream as measured
                "exploit_likelihood": Attribute.of_quarantined(0.9, self.name, T0, "audit-bias — unverifiable"),
            }),
            PartialSurface(key="CVE-C", domain="linux-kernel", source_name=self.name, fields={
                "subsystem": Attribute.of_measured("arch/x86/kvm", self.name, T0),
                "cwe": Attribute.of_open(self.name, T0),
                # dual-ref = guest-host chain (T4: the only clean cross-domain relatedness, interface-seam)
                "refs": Attribute.of_measured(
                    ["https://xenbits/advisory/XSA-999", "https://lore.kernel.org/kvm"], self.name, T0,
                    "coordinated-advisory, dual-ref chain"),
                "zone": Attribute.of_measured(Zone.REACHABLE, self.name, T0),
            }),
            # CVE-D, CVE-E: net/ipv4 (SAME subsystem as CVE-A) → exercises aggregate()
            PartialSurface(key="CVE-D", domain="linux-kernel", source_name=self.name, fields={
                "subsystem": Attribute.of_measured("net/ipv4", self.name, T0),
                "cwe": Attribute.of_open(self.name, T0),   # NVD will fill
                "zone": Attribute.of_measured(Zone.REACHABLE, self.name, T0),
            }),
            PartialSurface(key="CVE-E", domain="linux-kernel", source_name=self.name, fields={
                "subsystem": Attribute.of_measured("net/ipv4", self.name, T0),
                "cwe": Attribute.of_open(self.name, T0),   # NO NVD → stays OPEN (lowers element coverage)
                "zone": Attribute.of_measured(Zone.REACHABLE, self.name, T0),
            }),
        ]


class NvdStub:
    """SurfaceSource — NVD-like: provides only CWE, ABSENT for some CVEs (backlog). The join-enrichment source."""
    name = "nvd-stub"

    def produce(self):
        return [
            # CVE-A: NVD provides CWE → FILLS kernel-git's OPEN (join OPEN→MEASURED promotion)
            PartialSurface(key="CVE-A", domain="linux-kernel", source_name=self.name, fields={
                "cwe": Attribute.of_measured("CWE-416", self.name, T0, "NVD-join"),
            }),
            # CVE-C: NVD provides CWE
            PartialSurface(key="CVE-C", domain="linux-kernel", source_name=self.name, fields={
                "cwe": Attribute.of_measured("CWE-125", self.name, T0, "NVD-join"),
            }),
            # CVE-D: NVD provides CWE (second measured CWE in the net/ipv4 element)
            PartialSurface(key="CVE-D", domain="linux-kernel", source_name=self.name, fields={
                "cwe": Attribute.of_measured("CWE-125", self.name, T0, "NVD-join"),
            }),
            # CVE-B, CVE-E: NO NVD record (backlog) → cwe stays OPEN (OPEN≠null survivor case)
        ]


class HeuristicStub:
    """SurfaceSource — heuristic: DERIVES cwe (low-confidence). Exercises the trust-order conflict."""
    name = "heuristic-stub"

    def produce(self):
        return [
            # CVE-A: heuristic CWE-119 DERIVED. NVD MEASURED(CWE-416) MUST WIN (trust-order).
            PartialSurface(key="CVE-A", domain="linux-kernel", source_name=self.name, fields={
                "cwe": Attribute.of_derived("CWE-119", self.name, T0, "keyword-heuristic"),
            }),
        ]


class QuarantineStub:
    """SurfaceSource — suspect/audit-bias source: provides QUARANTINED cwe. Exercises OPEN-stickiness (decision-b)."""
    name = "quarantine-stub"

    def produce(self):
        return [
            # CVE-E: kernel-git OPEN + this QUARANTINED → after join must STAY OPEN (suspect data doesn't override abstention)
            PartialSurface(key="CVE-E", domain="linux-kernel", source_name=self.name, fields={
                "cwe": Attribute.of_quarantined("CWE-999", self.name, T0, "audit-bias guess — suspect"),
            }),
        ]


class SyzbotStub:
    """RealizationSource — syzbot-like: reachable-zone forward-realization, QUARANTINED (audit-bias)."""
    name = "syzbot-stub"

    def produce(self):
        return [
            RealizationEvent(
                surface_key="CVE-A", event_type="syzbot-crash", when=T0,
                status=Status.QUARANTINED, zone=Zone.REACHABLE, provenance=self.name,
                reason="syzbot reachable-zone crash — audit-bias, quarantined"),
            # CVE-B (hardware) → syzbot BLIND → no realization produced (deliberate gap, human-arm judges)
        ]


class AdvisoryStub:
    """RealizationSource — coordinated-advisory: chain-confirmation, verified → MEASURED."""
    name = "advisory-stub"

    def produce(self):
        return [
            RealizationEvent(
                surface_key="CVE-C", event_type="coordinated-advisory", when=T0,
                status=Status.MEASURED, zone=Zone.REACHABLE, provenance=self.name,
                reason="XSA dual-ref chain-confirmation — verified"),
        ]
