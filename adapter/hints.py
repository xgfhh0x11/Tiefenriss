"""
hints.py — DIRECTION-HINT layer (keyword-derived, DOES NOT ENTER THE SCORE).

Principle (the compare_subsystem verdict): keyword is DERIVED; its value is NOT in scoring
but in attention-steering. This layer only adds an ANNOTATION to a scored CPE surface
(MEASURED, D/tier UNCHANGED): "which sub-subsystem is active inside this lump".

╔══════════════════════════════════════════════════════════════════════════╗
║ STRICT BOUNDARY: this layer touches the core, ElementProfile, g_A/g_B/D    ║
║ NOT AT ALL. It produces a separate {sid: hint} dict; the adapter SHOWS it. ║
║ The score stays MEASURED; the hint is flagged DERIVED + low-confidence.    ║
║ Only CLEAN (single-match) assignments count; ambiguous/zero are excluded.  ║
╚══════════════════════════════════════════════════════════════════════════╝

Most valuable where CPE lumps things (linux:linux_kernel): "this strategic
UAF-in-kernel surface — look at mm/drm/ksmbd". On non-kernel surfaces
(chrome etc.) the kernel-keyword list does not match → empty hint (honest: no direction).
"""
import sqlite3
from collections import Counter

from .keyword_surfaces import match_subsys
from .surfaces import DB_DEFAULT

# The kernel-keyword list is applied ONLY to kernel-product surfaces. CHOSEN scope.
# Rationale: prevents cross-domain mis-matches (e.g. chrome "drm"=Digital Rights Mgmt,
# NOT kernel DRM graphics). Extensible (distro kernel CPEs can be added).
KERNEL_VPS = {"linux:linux_kernel"}


def _load_descriptions(cve_ids, db_path):
    conn = sqlite3.connect(db_path)
    out = {}
    ids = list(cve_ids)
    for i in range(0, len(ids), 900):     # SQLite IN() limiti
        chunk = ids[i:i + 900]
        q = "SELECT cve_id, description FROM cve_raw WHERE cve_id IN ({})".format(
            ",".join("?" * len(chunk)))
        for cid, desc in conn.execute(q, tuple(chunk)):
            out[cid] = desc or ""
    conn.close()
    return out


def direction_hints(surfaces: dict, db_path: str = DB_DEFAULT) -> dict:
    """
    {sid: hint} — the hint is a subsystem breakdown only from CLEAN single-match members.
    hint = {"subsystems": [(subsys, count)...], "covered": n, "total": m, "ambiguous": a}.
    A surface that produces no hint (no kernel-keyword match) IS NOT in the dict.
    """
    # only kernel-product surfaces (prevent cross-domain mis-matches)
    kernel_surfs = [s for s in surfaces.values() if s.vp in KERNEL_VPS]
    all_ids = set()
    for s in kernel_surfs:
        all_ids.update(s.members)
    desc = _load_descriptions(all_ids, db_path)

    hints = {}
    for s in kernel_surfs:
        tally = Counter()
        ambiguous = 0
        for cid in s.members:
            hits = match_subsys(desc.get(cid, ""))
            if len(hits) == 1:
                tally[hits[0]] += 1
            elif len(hits) > 1:
                ambiguous += 1
        if tally:
            hints[s.sid] = {
                "subsystems": tally.most_common(),
                "covered": sum(tally.values()),
                "total": len(s.members),
                "ambiguous": ambiguous,
            }
    return hints


def format_hint(hint: dict, top: int = 6) -> str:
    """Convert the hint to a one-line readable label (coverage transparent)."""
    subs = hint["subsystems"][:top]
    body = " ".join(f"{k}({c})" for k, c in subs)
    more = len(hint["subsystems"]) - len(subs)
    if more > 0:
        body += f" +{more}"
    return f"{body}  [kapsam {hint['covered']}/{hint['total']}" + \
           (f", belirsiz {hint['ambiguous']}" if hint["ambiguous"] else "") + "]"
