# 07 — Small Tasks (portability, v>1, keyword→score promotion)

Three small/deferred tasks. One of them (DB-path) is the first thing that will break on Rome.

---

## 7.1 — DB-path portability (FIRST TASK, Rome) → ✅ SOLVED (2026-07-16)

**Status:** ✅ SOLVED · **Effort:** very low · **Urgency:** high (would break on a new machine)

> IMPLEMENTED: `surfaces.py` DB_DEFAULT is now a `TIEFENRISS_DB` env override + a relative path
> anchored to the repo root (two directories up via `os.path`). Since all other modules import
> this, the single-point fix covered all of them. Verified: the path resolves (the file exists),
> env-override works, regression 7/7, run_poc connects to the DB (2947 surfaces). The absolute-path
> artifact is gone.

`adapter/surfaces.py::DB_DEFAULT` is an absolute path:
`/home/tylersec/Tiefenriss/prozessfall/prokaryotes/prozessfall.db`. On a new machine where the repo
lives at a different path, it breaks.

**Solution:** make it relative/config-driven. `prozessfall/config.toml` already holds the paths
(`prozessfall_config.py` reads it). Either read from there, or compute `DB_DEFAULT` relative to the repo root:
```python
import os
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # .../Tiefenriss
DB_DEFAULT = os.path.join(_REPO, "prozessfall", "prokaryotes", "prozessfall.db")
```
Verify regression + run_poc. (Since the DB file ships inside the repo, this relative path is portable.)

---

## 7.2 — v>1 normalization

**Status:** DEFERRED (deliberate) · **Effort:** low · **Urgency:** low

`v = v0·(g_A + w·g_B)` is sometimes >1 (when g_A+w·g_B > 1, e.g. 0.65+0.5·0.92). It does NOT
BREAK the hard-veto (the veto crushes low-v; v>1 only slightly nudges an already-saturated peak,
v^p is monotonic, no breakage). Decision-impact is ~zero.

**Why deferred:** no practical effect. **If it is to be solved, its place is: the adapter** (NOT
core.py — sealed). g_A and g_B are each normalized to [0,1]; they can be normalized together
(`positions.py`) or `min(g_A+w·g_B, 1)` at build time. It becomes necessary if v is read as a
probability in reporting / the AI arm.

**Violation:** do not touch core.py (value() is there). The fix is on the adapter side.

---

## 7.3 — keyword → score promotion (far future, with a validation gate)

**Status:** design-note · **Effort:** high · **Blocker:** validation gate + ground-truth

The keyword is currently a DIRECTION-HINT layer (`hints.py`), it does NOT ENTER the score
(correct — `TÜRETİLDİ`, it has failure modes: chrome "drm"=DRM cross-domain, 47% zero-coverage).
Its value is in "where to look."

**The ONLY disciplined way for it to affect the score** (the §11 mechanism): a keyword is a
hypothesis (like Type C) → it must pass through a **validation gate**. E.g.: keyword "ksmbd" →
does it really touch the `fs/smb/server/` patch (structural ground-truth, commit-colocation — see
02) → promote to `ÖLÇÜLDÜ` → only then does it legitimately refine g_A. A raw keyword NEVER enters g_A.

Architectural placement: the keyword is actually a proto-form of the 4th layer (the AI arm) — it
generates hypotheses and steers attention. No rush to promote it to the score; its highest value is
already in "where to look."

**Violation:** raw keyword → g_A/score is FORBIDDEN. Promotion only via the validation gate.

## Related files
`adapter/surfaces.py` (7.1), `adapter/positions.py`+`build.py` (7.2), `adapter/hints.py` (7.3).
