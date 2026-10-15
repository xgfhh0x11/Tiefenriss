"""
first_look_veri.py — AI-arm's FIRST recorded look at real kernel surfaces → the prediction notebook.

The İ7 clean-baseline STARTS here: these tip-2 predictions are recorded (held-out assigned, seed-invariant,
time-gate opened) so reality can judge them months later (#Ç4). ONE-WAY step (reviewer-authorized).

PROVENANCE (status-typed-record discipline): these predictions were produced by ME (Opus-4.8-as-operator,
this session), NOT the production Fable-5 (no ANTHROPIC_API_KEY in env). Marked on every record so the #Ç4
baseline reads the RIGHT operator's performance — plumbing/mechanics validation, NOT production performance.
Production Fable-5 (via API key) is the next pass; its predictions get their own provenance.

All 3 targets are stratejik → AT CEILING → tier_crossing BLOCKED → predictions use FUTURE_DETECTOR (kat-2).
One deliberate tier_crossing is included → tavan-guard rejects it (goes to red-log, NOT the notebook).
"""
from __future__ import annotations

import json

from .ongoru_defteri import OngoruDefteri, DEFTER_YOLU_DEFAULT
from .llm_operator import RecordedBackend, run_operator
from .veri_bridge import veri_contexts
from .yayim import emit_batch

CREATED_TS = "2026-07-21"      # caller-supplied (no now() embedded)
PROVENANCE = ("operatör=Opus-4.8-as-operator (bu-oturum); üretim-Fable-5-DEĞİL (API-key-yok). "
              "#Ç4-baseline bu-provenance'a-göre okunmalı: plumbing+mekanik-doğrulama, üretim-performansı-DEĞİL.")
TARGETS = ["fs/smb", "net/netfilter", "kernel/bpf"]


def _fd(pt, vc, mech, det, hor, fals, tgt=None):
    d = {"pred_type": pt, "vuln_class": vc, "mechanism": mech, "signal_kind": "future_detector",
         "detector_name": det, "signal_horizon_days": hor, "falsification_method": fals}
    if tgt:
        d["target_ref"] = tgt
    return d


# MY genuine operator cognition on the real surfaces (grounded in their measured CWE-distributions)
RECORDED = {
  ("fs/smb", "teknik"): json.dumps([
     _fd("stress_point", "CWE-416",
         "ksmbd session/tree-connect refcount underflow: connection teardown frees the session while an "
         "in-flight SMB2 request on another worker still holds a raw pointer → UAF write on session struct",
         "new fs/smb CVE or syzbot crash root-caused to ksmbd session/tcon lifetime under concurrent request+logoff",
         365, "no session-lifetime UAF surfaces in fs/smb within horizon → weakens the concurrent-teardown hypothesis"),
     _fd("transition", "CWE-787",
         "compound SMB2 request: a chained sub-request's offset/length validated against the PREVIOUS buffer's "
         "bound → OOB write; pivot from a session-UAF heap-layout leak to a controlled linear overwrite",
         "OOB-write CVE in ksmbd SMB2 compound/parse path (offset validation vs wrong buffer)", 540,
         "no compound-parse OOB within horizon → the chained-offset hypothesis is not load-bearing", tgt="fs/smb"),
  ]),
  ("fs/smb", "tarihsel"): json.dumps([
     _fd("stress_point", "CWE-476",
         "young protocol server pattern: NULL-deref clusters in optional/rare SMB2 command handlers reached "
         "before full session state is established (handler assumes a struct set up by an earlier command)",
         "NULL-deref CVE in a rare/optional ksmbd SMB2 command dispatch path", 365,
         "no such pre-setup NULL-deref within horizon → the immature-handler pattern doesn't hold here"),
  ]),
  ("fs/smb", "psikolojik"): json.dumps([   # DELIBERATE ceiling violation → tavan-guard must reject
     {"pred_type": "stress_point", "vuln_class": "CWE-416",
      "mechanism": "ksmbd will keep producing UAFs so its value will rise",
      "signal_kind": "tier_crossing", "falsification_method": "the surface crosses the core tier upward"},
  ]),
  ("net/netfilter", "teknik"): json.dumps([
     _fd("stress_point", "CWE-416",
         "nf_tables set/chain freed during a concurrent transaction commit while a packet-path lookup still "
         "references it (abort/commit race outside the intended RCU grace) → UAF on the set element",
         "UAF CVE in nf_tables set/chain lifetime under concurrent transaction (syzbot nft race)", 365,
         "no transaction-race UAF in net/netfilter within horizon → the commit/abort-race hypothesis weakens"),
  ]),
  ("net/netfilter", "epistemik"): json.dumps([
     _fd("stress_point", "CWE-362",
         "the ASSUMED invariant that every nft object access sits inside an RCU read section is broken on a "
         "control-path (dump/getset) that touches an object being torn down → TOCTOU race",
         "race/TOCTOU CVE in an nf_tables dump/get control path vs concurrent delete", 540,
         "no control-path race within horizon → the RCU-everywhere assumption held (prediction wrong)"),
  ]),
  ("kernel/bpf", "teknik"): json.dumps([
     _fd("stress_point", "CWE-787",
         "verifier register bounds-tracking gap: a newly-added instruction/ALU-op propagates min/max bounds "
         "incorrectly, letting a scalar be treated as in-range → OOB write through a map/stack pointer",
         "OOB-write CVE root-caused to BPF verifier bounds-tracking on a specific op/helper", 540,
         "no verifier bounds-tracking OOB within horizon → bounds-propagation is currently tight (prediction wrong)"),
  ]),
  ("kernel/bpf", "psikolojik"): json.dumps([
     _fd("stress_point", "CWE-416",
         "defenders assume the verifier is exhaustive; attackers probe NEWLY-added kfuncs/helpers where "
         "refcount/lifetime rules lag the verifier's tracking → a released kernel object stays usable in-prog",
         "UAF CVE tied to a recently-added BPF kfunc/helper object-lifetime gap", 540,
         "no new-kfunc lifetime UAF within horizon → helper-verification kept pace (prediction wrong)"),
  ]),
}


def record(defter_path: str = DEFTER_YOLU_DEFAULT) -> tuple[OngoruDefteri, dict]:
    """Load notebook, run the recorded operator on the 3 real surfaces, emit (provenance-marked), save."""
    defter = OngoruDefteri.load(defter_path)
    backend = RecordedBackend(RECORDED)
    ctxs = {c.surface_id: c for c in veri_contexts()}
    cands = []
    for sid in TARGETS:
        cands.extend(run_operator(ctxs[sid], backend, ctxs[sid].tier))
    rep = emit_batch(defter, cands, CREATED_TS, provenance=PROVENANCE)
    defter.save(defter_path)
    return defter, rep


if __name__ == "__main__":
    record()
