"""
kernel_git.py — SurfaceSource: git.kernel.org/.../vulns.git (Linux-CNA, since Feb-2024).

Produces (per-CVE PartialSurface):
  subsystem  MEASURED  — primary subsystem from the commit-path (always-MEASURED anchor; needs no join)
  shas       MEASURED  — fixing-commits (colocation/realization-match anchor)
  files      MEASURED  — touched files
  cwe        OPEN      — kernel-CNA assigns NO CWE (git_rows cwe=null → no fabrication, leave-open)
  refs       (absent)  — refs NOT in the git_rows extraction → join OPEN-fills (KNOWN-GAP, reported below)
"""
from __future__ import annotations

import json
import os

from ..status import Attribute
from ..record import PartialSurface
from . import DATA_DIR


def norm_subsystem(path: str) -> str:
    """
    Structural granularity: the 2-level directory of a file path (decision, 2026-07-20; MAINTAINERS-mapping
    deferred). Drops the filename, keeps ≤2 dir levels. Chosen BLIND to g_A/realization (structural rule only).
    e.g. net/ipv4/tcp.c → net/ipv4 · crypto/lzo-rle.c → crypto · drivers/gpu/drm/amd/x.c → drivers/gpu
    """
    parts = path.split("/")
    dirs = parts[:-1] if ("." in parts[-1]) else parts   # drop trailing filename
    return "/".join(dirs[:2]) if dirs else path


def _subsystems_from_files(files: list[str]) -> list[str]:
    """Unique 2-level-dir subsystems touched, ordered by touch-frequency (primary = most-touched, det. tie-break)."""
    count: dict[str, int] = {}
    order: list[str] = []
    for f in files:
        s = norm_subsystem(f)
        if s not in count:
            order.append(s)
        count[s] = count.get(s, 0) + 1
    return sorted(order, key=lambda s: (-count[s], order.index(s)))


class KernelGitSource:
    name = "kernel-cve-git"

    def __init__(self, path: str | None = None, stamp: str = "2026-07-19"):
        self.path = path or os.path.join(DATA_DIR, "git_rows.json")
        self.stamp = stamp

    def produce(self):
        rows = json.load(open(self.path, encoding="utf-8"))
        for cve, row in rows.items():
            files = row.get("files") or []
            subs = _subsystems_from_files(files)          # granularity-normalized (2-level-dir from files)
            fields: dict[str, Attribute] = {
                # cwe ALWAYS open: kernel-CNA does not assign. NVD-join fills later (or stays OPEN).
                "cwe": Attribute.of_open(self.name, self.stamp, "kernel-CNA assigns no CWE (git cwe=null)"),
            }
            if subs:
                fields["subsystem"] = Attribute.of_measured(subs[0], self.name, self.stamp, "2-level-dir, most-touched (primary)")
                fields["subsystems_full"] = Attribute.of_measured(subs, self.name, self.stamp, "all 2-level-dir subsystems touched")
            else:
                # no file/subsystem-anchor → OPEN (aggregate skips honestly; count reported)
                fields["subsystem"] = Attribute.of_open(self.name, self.stamp, "no subsystem from files")
            if row.get("shas"):
                fields["shas"] = Attribute.of_measured(row["shas"], self.name, self.stamp, "fixing-commits")
            if row.get("files"):
                fields["files"] = Attribute.of_measured(row["files"], self.name, self.stamp, "touched files")
            yield PartialSurface(key=cve, domain="linux-kernel", source_name=self.name, fields=fields)
