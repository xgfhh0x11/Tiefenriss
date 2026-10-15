"""
syzbot.py — RealizationSource: syzkaller.appspot.com fixed-bugs (reachable-zone realization).

Produces (RealizationEvent): when a syzbot-bug links to a CVE via fix_commit_sha ∈ CVE.shas. status=QUARANTINED
(T4: audit-bias — syzbot reach is selective, it is a realization-CANDIDATE not PROOF; #Ç4 judges), zone=REACHABLE
(syzbot only fuzzes syscall-reachable code → realization only in the reachable-zone).

`reachable_subsystems()` — the set of subsystems syzbot has crashed in (for zone-enrichment: if a subsystem is
syzbot-reachable, a CVE there is DERIVED reachable — a direct match is MEASURED reachable).
İ9a: a syzbot EVENT (crash/fix) is a realization-candidate; NOT engagement.
"""
from __future__ import annotations

import json
import os

from ..status import Status
from ..record import RealizationEvent, Zone
from . import DATA_DIR


def _load(path):
    return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]


class SyzbotSource:
    name = "syzbot"

    def __init__(self, path: str | None = None, sha_to_cve: dict | None = None, stamp: str = "2026-07-19"):
        self.path = path or os.path.join(DATA_DIR, "syzbot.jsonl")
        self.sha_to_cve = sha_to_cve or {}      # {sha|sha[:12]: cve} — the runner builds it from kernel-git
        self.stamp = stamp
        self._rows = None

    def _read(self):
        if self._rows is None:
            self._rows = _load(self.path)
        return self._rows

    def _matched_cve(self, s) -> str | None:
        fsha = s.get("fix_commit_sha")
        if not fsha:
            return None
        return self.sha_to_cve.get(fsha) or self.sha_to_cve.get(fsha[:12])

    def produce(self):
        for s in self._read():
            cve = self._matched_cve(s)
            if cve is None:
                continue      # a syzbot-bug not linkable to a CVE → NOT a realization event (honest)
            yield RealizationEvent(
                surface_key=cve, event_type="syzbot-crash",
                when=s.get("first_crash_time") or "", status=Status.QUARANTINED, zone=Zone.REACHABLE,
                provenance=self.name, reason="syzbot reachable-zone crash — audit-bias, quarantined (#Ç4 judges)")

    def reachable_subsystems(self) -> set:
        """The subsystems syzbot has crashed in (basis for zone-enrichment)."""
        out = set()
        for row in self._read():
            for sub in (row.get("subsystem") or []):
                if sub:
                    out.add(sub)
        return out

    def directly_matched_cves(self) -> set:
        """CVEs directly linked to a syzbot-bug via fix_commit_sha (basis for zone=MEASURED)."""
        return {c for c in (self._matched_cve(s) for s in self._read()) if c}
