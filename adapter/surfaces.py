"""
surfaces.py — Prozessfall SQLite → CPE-CLEAN surface list.

surface (element) = (primary_cwe, vendor:product).
  • primary_cwe = the FIRST item of cwe_ids. CHOSEN: "first-listed = primary".
    (The NVD order is not always root-cause order; a known approximation.)
  • vendor:product = from CPE 2.3 (affected). CPE-CLEAN: only real CPE data.
    We DO NOT GUESS the subsystem from description text (separate, later work — no mixing).

A surface = "this bug-class, in this subsystem." The member CVEs are that surface's
SIGNAL PULSES over time (the raw input of π).

All MEASURED (Type A): CWE and CPE are read mechanically from data, no judgment.
"""
import json
import os
import sqlite3
from collections import defaultdict
from datetime import date

# DB-path portability (07_kucuk_isler 7.1): an absolute path would break on a new machine.
# Priority: (1) TIEFENRISS_DB env override, (2) relative path anchored to the repo root.
# surfaces.py → under adapter/; repo root is two dirs up. The DB ships inside the repo, so it is portable.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # .../Tiefenriss
DB_DEFAULT = os.environ.get("TIEFENRISS_DB") or os.path.join(
    _REPO_ROOT, "prozessfall", "prokaryotes", "prozessfall.db"
)


def _vps(affected_json: str) -> set[str]:
    """{vendor:product} set from a CPE 2.3 list. Broken/missing CPE is skipped."""
    out = set()
    for cpe in (json.loads(affected_json) if affected_json else []):
        p = cpe.split(":")
        if len(p) > 5 and p[3] and p[4]:
            out.add(f"{p[3]}:{p[4]}")
    return out


class Surface:
    """A CPE-clean surface + member CVE pulses. The adapter's raw material."""
    __slots__ = ("cwe", "vp", "members", "days", "cvss", "places")

    def __init__(self, cwe, vp):
        self.cwe = cwe            # primary CWE
        self.vp = vp              # vendor:product (subsystem)
        self.members = []         # [cve_id]
        self.days = []            # [date] — publication days (signal pulses)
        self.cvss = []            # [float|None] — for reporting only, DOES NOT ENTER v0
        self.places = set()       # the distinct places this surface's MEMBERS touch
                                  # (vendor:product) — the raw input of ρ (its OWN spread,
                                  # NOT cwe-footprint → no double-count on fine-grained)

    @property
    def key(self):
        return (self.cwe, self.vp)

    @property
    def sid(self):
        return f"{self.cwe}×{self.vp}"


def load_surfaces(db_path: str = DB_DEFAULT, min_pulses: int = 1):
    """
    DB → {(cwe, vp): Surface}. A pulse-count filter via min_pulses.

    Also returns:
      cwe_footprint: {cwe: set(vp)} — the products a CWE spreads across (CPE-clean)
        (spread_count / the raw input of ρ — the spatial footprint of the invariant).
    """
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT cve_id, published, cvss_score, cwe_ids, affected FROM cve_raw"
    ).fetchall()
    conn.close()

    surfaces: dict[tuple, Surface] = {}
    cwe_footprint: dict[str, set] = defaultdict(set)

    for cid, pub, cvss, cwe_json, aff in rows:
        cwes = json.loads(cwe_json) if cwe_json else []
        if not cwes:
            continue
        primary = cwes[0]
        day = None
        if pub:
            try:
                day = date.fromisoformat(pub[:10])
            except ValueError:
                day = None
        member_vps = _vps(aff)                 # ALL the places this CVE touches
        for vp in member_vps:
            cwe_footprint[primary].add(vp)
            k = (primary, vp)
            s = surfaces.get(k)
            if s is None:
                s = surfaces[k] = Surface(primary, vp)
            s.members.append(cid)
            if day:
                s.days.append(day)
            s.cvss.append(cvss)
            s.places |= member_vps             # every place the member touches is added to the
                                               # surface's OWN spread (ρ input)

    if min_pulses > 1:
        surfaces = {k: s for k, s in surfaces.items() if len(s.members) >= min_pulses}

    return surfaces, dict(cwe_footprint)
