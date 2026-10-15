"""
keyword_surfaces.py — subsystem surfaces DERIVED FROM DESCRIPTION TEXT.

╔══════════════════════════════════════════════════════════════════════════╗
║ EPISTEMIC STATUS: DERIVED/GENERATED (INFERENCE) — SEPARATE from CPE-clean. ║
║ CPE surface (surfaces.py) = MEASURED (Type A). Here the subsystem is       ║
║ GUESSED from a word in the description → weaker epistemic status. The two  ║
║ are NEVER MIXED in the same g_A graph (otherwise part of g_A is measured,  ║
║ part guessed, inseparable — it corrupts the whole epistemics). This module ║
║ produces a separate universe; see compare_subsystem.py (SIDE BY SIDE).     ║
╚══════════════════════════════════════════════════════════════════════════╝

DISCIPLINE: only SINGLE-match (clean) CVEs enter a surface. Multi-match
(ambiguous) and zero-match (unrecoverable) are EXCLUDED — noise is not let in,
coverage loss is reported transparently.
"""
import re
import json
import sqlite3
from collections import defaultdict
from datetime import date

from .surfaces import Surface, DB_DEFAULT, _vps

# Curated Linux kernel subsystem keyword list (word-bounded). CHOSEN list.
KERNEL_SUBSYS = {
    "ksmbd": [r"ksmbd"], "cifs": [r"\bcifs\b", r"\bsmb\b"],
    "netfilter": [r"netfilter", r"nf_tables", r"nftables", r"\bnft\b", r"conntrack", r"xt_", r"ipset"],
    "io_uring": [r"io_uring", r"io uring"], "bpf": [r"\be?bpf\b", r"\bxdp\b"],
    "tcp": [r"\btcp\b"], "udp": [r"\budp\b"], "ipv6": [r"ipv6"], "ipv4": [r"ipv4"],
    "xfs": [r"\bxfs\b"], "ext4": [r"ext4"], "btrfs": [r"btrfs"], "f2fs": [r"f2fs"],
    "nfs": [r"\bnfsd?\b"], "overlayfs": [r"overlayfs", r"overlay filesystem"],
    "fuse": [r"\bfuse\b"], "nvme": [r"\bnvme\b"], "scsi": [r"\bscsi\b"],
    "usb": [r"\busb\b"], "bluetooth": [r"bluetooth", r"\bhci\b", r"l2cap"],
    "drm": [r"\bdrm\b", r"i915", r"amdgpu", r"nouveau", r"\bgpu\b"],
    "kvm": [r"\bkvm\b"], "vfio": [r"vfio"], "vhost": [r"vhost"], "tty": [r"\btty\b"],
    "pci": [r"\bpci\b"], "acpi": [r"acpi"], "alsa": [r"\balsa\b", r"sound/"],
    "wifi": [r"mac80211", r"cfg80211", r"\bwifi\b", r"\bwlan\b"],
    "can": [r"\bcan bus\b", r"can_"], "cgroup": [r"cgroup"], "keyring": [r"keyring", r"keyctl"],
    "perf": [r"perf_event", r"\bperf\b"], "futex": [r"futex"], "pipe": [r"pipe_"],
    "mm": [r"\bmm/\b", r"\bslub\b", r"\bslab\b", r"mmap", r"page fault"],
    "rds": [r"\brds\b"], "sctp": [r"sctp"], "tipc": [r"tipc"], "ppp": [r"\bppp\b"],
}
_COMPILED = {k: [re.compile(p, re.I) for p in ps] for k, ps in KERNEL_SUBSYS.items()}


def _is_kernel(desc, affected_json):
    if desc and "linux kernel" in desc.lower():
        return True
    for cpe in (json.loads(affected_json) if affected_json else []):
        if "linux:linux_kernel" in cpe:
            return True
    return False


def match_subsys(desc):
    """Subsystems matched in the description (0/1/many). DERIVED."""
    d = desc or ""
    return [k for k, ps in _COMPILED.items() if any(p.search(d) for p in ps)]


def load_keyword_surfaces(db_path: str = DB_DEFAULT):
    """
    CLEAN (single-match) keyword-surfaces from kernel CVEs.
    → (surfaces {(cwe,subsys): Surface}, footprint {cwe:set(subsys)}, stats dict).
    stats: clean/ambiguous/zero reliability breakdown (transparency).
    """
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT cve_id, published, cvss_score, cwe_ids, description, affected FROM cve_raw"
    ).fetchall()
    conn.close()

    surfaces, footprint = {}, defaultdict(set)
    n_kernel = clean = ambiguous = zero = 0
    for cid, pub, cvss, cwe_json, desc, aff in rows:
        if not _is_kernel(desc, aff):
            continue
        n_kernel += 1
        hits = match_subsys(desc)
        if len(hits) == 0:
            zero += 1; continue
        if len(hits) > 1:
            ambiguous += 1; continue     # ambiguous → EXCLUDE (noise is not let in)
        clean += 1
        cwes = json.loads(cwe_json) if cwe_json else []
        if not cwes:
            continue
        primary = cwes[0]
        subsys = hits[0]
        day = None
        if pub:
            try:
                day = date.fromisoformat(pub[:10])
            except ValueError:
                day = None
        footprint[primary].add(subsys)
        k = (primary, subsys)
        s = surfaces.get(k)
        if s is None:
            s = surfaces[k] = Surface(primary, subsys)
        s.members.append(cid)
        if day:
            s.days.append(day)
        s.cvss.append(cvss)
        # ρ input: the real places the member touches (CPE vendor:product). Most kernel
        # CVEs are linux:linux_kernel → narrow surface → ρ low (the artefact is resolved).
        s.places |= _vps(aff)

    stats = {"n_kernel": n_kernel, "clean": clean,
             "ambiguous": ambiguous, "zero": zero}
    return surfaces, dict(footprint), stats
