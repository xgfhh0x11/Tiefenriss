"""
refs.py — SurfaceSource: cross-references from the vulns/ CVE-5.0 JSON (containers.cna.references[]).

Produces (per-CVE PartialSurface):
  refs           MEASURED  — all reference URLs (mechanically read from JSON; the census 0-refs blind-spot closed)
  external_refs  MEASURED  — the cross-project subset (host NOT kernel.org) = the "seam/attention" seed. MEASURED
                             even when EMPTY (we looked and found none — not OPEN).

IMPORTANT (measured 2026-07-20): kernel-CVE-git refs are ~100% git.kernel.org fix-commits (the CNA lists the
fixing commits). Cross-project refs are RARE (~0.5%) and are RESEARCHER-ATTENTION (Project Zero / ZDI / blogs),
NOT guest-host advisories (zero xenbits/qemu). So this source captures fix-commit provenance + a small
attention-signal; the guest-host SEAM-edge, if it exists, lives in another source (Xen XSA), not here.
"""
from __future__ import annotations

import json
import os
from urllib.parse import urlparse

from ..status import Attribute
from ..record import PartialSurface
from . import DATA_DIR


# Hosts counted as "the kernel's own infrastructure" (fix-commits / list / bugzilla). A ref to any OTHER host
# is cross-project (a seam/attention seed). Not the value itself — a signal to inspect.
KERNEL_HOSTS = {
    "git.kernel.org", "lore.kernel.org", "www.kernel.org", "kernel.org",
    "bugzilla.kernel.org", "patchwork.kernel.org",
}


def _host(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def external_refs(urls: list[str]) -> list[str]:
    """Cross-project references (host not in KERNEL_HOSTS) = seam/attention seeds."""
    return [u for u in urls if _host(u) and _host(u) not in KERNEL_HOSTS]


class RefsSource:
    name = "kernel-cve-git-refs"

    # search order for a CVE's JSON (published is the main one)
    _SUBDIRS = ("published", "testing/published", "rejected", "reserved")

    def __init__(self, root: str | None = None, only: set | None = None, stamp: str = "2026-07-20"):
        self.root = root or os.path.join(DATA_DIR, "vulns", "cve")
        self.only = only          # None → skip (needs a CVE-set to resolve paths); set → these CVEs
        self.stamp = stamp

    def _find(self, cve: str) -> str | None:
        year = cve.split("-")[1]
        for sub in self._SUBDIRS:
            p = os.path.join(self.root, sub, year, f"{cve}.json")
            if os.path.exists(p):
                return p
        return None

    def produce(self):
        if self.only is None:
            return
        for cve in self.only:
            p = self._find(cve)
            if p is None:
                continue      # no JSON → no refs contribution (honest; kernel-git already OPEN-fills refs)
            d = json.load(open(p, encoding="utf-8"))
            raw = d.get("containers", {}).get("cna", {}).get("references", [])
            urls = [r.get("url", "") for r in raw if r.get("url")]
            if not urls:
                continue
            ext = external_refs(urls)
            fields = {
                "refs": Attribute.of_measured(urls, self.name, self.stamp, "CVE-5.0 references[] (mechanical)"),
                # MEASURED even if empty: we looked. Empty = "no cross-project ref", not "unknown".
                "external_refs": Attribute.of_measured(
                    ext, self.name, self.stamp,
                    f"{len(ext)} cross-project (non-kernel.org) — seam/attention seed"),
            }
            yield PartialSurface(key=cve, domain="linux-kernel", source_name=self.name, fields=fields)
