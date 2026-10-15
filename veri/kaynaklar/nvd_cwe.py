"""
nvd_cwe.py — SurfaceSource: NVD-join (fills the CWE the kernel-CNA does not assign).

Produces (per-CVE PartialSurface): cwe MEASURED (when NVD has a usable CWE). FILLS kernel-git's OPEN at join
(OPEN→MEASURED promotion). If `only` is given, contributes only to that CVE-set (restrict to the kernel-set so
non-kernel NVD-CVEs don't inflate MergedRecord). Measured real coverage: ~61% (2026-07-19).
"""
from __future__ import annotations

import json
import os

from ..status import Attribute
from ..record import PartialSurface
from . import DATA_DIR


class NvdCweSource:
    name = "nvd-cwe-join"

    def __init__(self, path: str | None = None, only: set | None = None, stamp: str = "2026-07-19"):
        self.path = path or os.path.join(DATA_DIR, "nvd_cwe.json")
        self.only = only          # None → all; set → only these CVEs (kernel-set restriction)
        self.stamp = stamp

    def produce(self):
        cwe_map = json.load(open(self.path, encoding="utf-8"))["cwe_map"]
        for cve, cwe in cwe_map.items():
            if self.only is not None and cve not in self.only:
                continue
            if cwe and str(cwe).startswith("CWE-"):     # usable CWE (noinfo/other skipped)
                yield PartialSurface(key=cve, domain="linux-kernel", source_name=self.name,
                                     fields={"cwe": Attribute.of_measured(cwe, self.name, self.stamp, "NVD-join")})
