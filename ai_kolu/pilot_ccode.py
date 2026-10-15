"""
pilot_ccode.py — (b) PILOT: Claude-Code-internal operator (Opus-4.8, Max, NO API key) on ~20 reachable surfaces.

GOAL: ACTIVATE held-out (0→3) and verify the held-out chain at scale → the #Ç4 baseline starts. This is NOT
production Fable-5 → provenance marked accordingly (SEPARATE from a future Fable-5 batch; consistent with the
earlier opus-as-operator 7). Grounded in each surface's REAL measured CWE-distribution.

Exposure-BLIND operator (sealed A1): produces for ALL surfaces incl. held-out; held-out predictions are recorded
but HIDDEN at presentation (user_visible excludes them) — THAT is the self-fulfilling defense. (Held-out must
have predictions, else #Ç4 has nothing to compare.)

Ceiling-discipline: stratejik(=ceiling) → FUTURE_DETECTOR (kat-2, detector_name+bounded horizon).
taktik(=not-ceiling) → TIER_CROSSING (kat-1, realizes when a future CVE pushes the surface's tier upward).
"""
from __future__ import annotations

import json

from .ongoru_defteri import OngoruDefteri, DEFTER_YOLU_DEFAULT
from .llm_operator import RecordedBackend, run_operator
from .veri_bridge import veri_contexts
from .yayim import emit_batch

CREATED_TS = "2026-07-22"
PROVENANCE = ("operator=opus-4.8-as-operator (claude-code/Max, pilot-batch-2 2026-07-22); production=false. "
              "#Ç4-baseline: NOT production-Fable-5; held-out-chain scale-validation + baseline-start.")

TARGETS = [  # (subsystem, tier) — depth-stratified reachable, done-excluded; held-out assigned deterministically
    ("net/bluetooth","stratejik"),("mm","stratejik"),("net/sched","stratejik"),("fs/btrfs","stratejik"),
    ("net/ipv6","stratejik"),("net/ipv4","stratejik"),("net/core","stratejik"),("kernel/trace","stratejik"),
    ("fs/f2fs","stratejik"),("fs/ext4","stratejik"),("fs","stratejik"),("fs/nfsd","stratejik"),
    ("block","taktik"),("net/mptcp","taktik"),("fs/ocfs2","taktik"),("io_uring","taktik"),
    ("net/sctp","taktik"),("fs/nilfs2","taktik"),("fs/nfs","taktik"),("net/rxrpc","taktik"),
]


def _fd(pt, vc, mech, det, hor, fals):   # future_detector (stratejik/ceiling → kat-2)
    return {"pred_type": pt, "vuln_class": vc, "mechanism": mech, "signal_kind": "future_detector",
            "detector_name": det, "signal_horizon_days": hor, "falsification_method": fals}


def _tc(pt, vc, mech):                    # tier_crossing (taktik/non-ceiling → kat-1)
    return {"pred_type": pt, "vuln_class": vc, "mechanism": mech, "signal_kind": "tier_crossing",
            "falsification_method": "a future CVE of this class raises the surface's core tier above taktik"}


def _j(*cands):
    return json.dumps(list(cands))


# MY genuine operator cognition (teknik lens), grounded in each surface's measured primary-CWE
RECORDED = {
  ("net/bluetooth","teknik"): _j(_fd("stress_point","CWE-416",
     "L2CAP/HCI connection object freed on remote disconnect while a queued incoming PDU still references it "
     "(connect/disconnect race over the HCI event path) → UAF on the connection struct",
     "UAF CVE in bluetooth L2CAP/HCI connection lifetime under connect/disconnect race",365,
     "no connection-lifetime UAF in net/bluetooth within horizon → the disconnect-race hypothesis weakens")),
  ("mm","teknik"): _j(_fd("stress_point","CWE-362",
     "VMA/anon_vma lifetime race: concurrent mmap/munmap/fork lets a page-fault path walk a VMA being torn down "
     "outside the mmap_lock ordering → TOCTOU on the VMA, escalating to UAF on the anon_vma chain",
     "race/UAF CVE in mm VMA/anon_vma under concurrent mmap/munmap/fork",365,
     "no VMA-lifetime race in mm within horizon → the mmap-lock-ordering assumption held")),
  ("net/sched","teknik"): _j(_fd("stress_point","CWE-416",
     "qdisc/filter object freed during a concurrent `tc` reconfiguration while the packet-enqueue path still "
     "holds it (RTNL vs data-path race) → UAF on the qdisc/classifier",
     "UAF CVE in net/sched qdisc/filter lifetime under concurrent tc reconfig",365,
     "no qdisc-lifetime UAF in net/sched within horizon → the RTNL/data-path race hypothesis weakens")),
  ("fs/btrfs","teknik"): _j(_fd("stress_point","CWE-362",
     "extent-buffer/inode reference race under concurrent write + snapshot/balance → a torn-down extent buffer "
     "is walked by another thread → UAF via the extent tree",
     "race/UAF CVE in btrfs extent-buffer/inode under concurrent write+snapshot/balance",540,
     "no extent-buffer race in fs/btrfs within horizon → the concurrent-snapshot hypothesis weakens")),
  ("net/ipv6","teknik"): _j(_fd("stress_point","CWE-416",
     "fragment-reassembly queue freed on timeout while a late fragment is still being processed → UAF on the "
     "frag_queue (reassembly timer vs input race)",
     "UAF CVE in ipv6 fragment reassembly (frag_queue timer/input race)",365,
     "no frag-reassembly UAF in net/ipv6 within horizon → the timer/input race hypothesis weakens")),
  ("net/ipv4","teknik"): _j(_fd("stress_point","CWE-476",
     "NULL-deref on a rarely-exercised IP option / control path where a socket/route field is assumed set up by "
     "an earlier state but is reachable before initialization under crafted setsockopt ordering",
     "NULL-deref CVE in ipv4 option/route control path under crafted setsockopt ordering",365,
     "no such pre-init NULL-deref in net/ipv4 within horizon → the ordering-assumption held")),
  ("net/core","teknik"): _j(_fd("stress_point","CWE-416",
     "skb/sk lifetime UAF in a core datapath: an skb queued to a socket receive path is freed on socket close "
     "while a softirq still dereferences it (close vs softirq race)",
     "UAF CVE in net/core skb/sk lifetime under socket-close vs softirq race",365,
     "no skb/sk-lifetime UAF in net/core within horizon → the close/softirq race hypothesis weakens")),
  ("kernel/trace","teknik"): _j(_fd("stress_point","CWE-416",
     "ftrace/tracepoint ring-buffer or trace_event object freed during concurrent trace reconfiguration while a "
     "tracing path still writes to it → UAF on the trace buffer/event",
     "UAF CVE in ftrace/tracepoint buffer/event under concurrent trace reconfig",540,
     "no trace-buffer UAF in kernel/trace within horizon → the reconfig-race hypothesis weakens")),
  ("fs/f2fs","teknik"): _j(_fd("stress_point","CWE-125",
     "OOB-read in f2fs metadata (NAT/SIT/checkpoint) parsing on a crafted image: an on-disk index/count is "
     "trusted without bound-checking against the block size → out-of-bounds read during mount/GC",
     "OOB-read CVE in f2fs metadata (NAT/SIT/checkpoint) parsing on crafted image",540,
     "no metadata OOB-read in fs/f2fs within horizon → the trusted-on-disk-index hypothesis weakens")),
  ("fs/ext4","teknik"): _j(_fd("stress_point","CWE-125",
     "OOB-read via crafted extent tree: a manipulated extent header depth/entries field is trusted, letting the "
     "extent walker read past the block buffer during lookup",
     "OOB-read CVE in ext4 extent-tree walk on crafted image",540,
     "no extent-tree OOB-read in fs/ext4 within horizon → the trusted-extent-header hypothesis weakens")),
  ("fs","teknik"): _j(_fd("stress_point","CWE-416",
     "VFS dentry/inode lifetime UAF: a dentry freed during concurrent rename/unlink is still referenced by a "
     "path-walk (RCU-walk vs teardown race) → UAF on the dentry",
     "UAF CVE in VFS dentry/inode lifetime under rename/unlink vs path-walk race",540,
     "no dentry-lifetime UAF in fs within horizon → the RCU-walk/teardown race hypothesis weakens")),
  ("fs/nfsd","teknik"): _j(_fd("stress_point","CWE-416",
     "nfsd open/lock-state or session slot freed under concurrent client RPCs (state-teardown vs in-flight-RPC "
     "race) while still referenced → UAF on the nfs4 state object",
     "UAF CVE in nfsd open/lock/session state lifetime under concurrent RPC",365,
     "no state-lifetime UAF in fs/nfsd within horizon → the RPC-teardown race hypothesis weakens")),
  # --- taktik (tier_crossing, kat-1) ---
  ("block","teknik"): _j(_tc("stress_point","CWE-416",
     "request_queue/gendisk object UAF: concurrent I/O submission during device removal dereferences a torn-down "
     "queue (hot-unplug vs in-flight-bio race)")),
  ("net/mptcp","teknik"): _j(_tc("stress_point","CWE-362",
     "subflow lifetime race: concurrent path-management (add/remove subflow) vs the data path frees a subflow "
     "context still referenced by the send/recv path → TOCTOU escalating to UAF")),
  ("fs/ocfs2","teknik"): _j(_tc("stress_point","CWE-476",
     "NULL-deref on a crafted ocfs2 volume: a cluster-metadata field (dinode/extent) assumed present is missing, "
     "reached before validation during mount → NULL pointer dereference")),
  ("io_uring","teknik"): _j(_tc("stress_point","CWE-416",
     "request (io_kiocb) or fixed-file/buffer lifetime UAF: a request completes/cancels while a linked or async "
     "worker path still references it (cancel vs completion race)")),
  ("net/sctp","teknik"): _j(_tc("stress_point","CWE-908",
     "use of uninitialized association/chunk field on a malformed inbound packet: a parameter length lets a "
     "handler read a field the parser never populated")),
  ("fs/nilfs2","teknik"): _j(_tc("stress_point","CWE-787",
     "OOB-write on a crafted nilfs2 image: a segment/checkpoint on-disk count is trusted, letting a copy write "
     "past a fixed buffer during mount/recovery")),
  ("fs/nfs","teknik"): _j(_tc("stress_point","CWE-476",
     "client-side NULL-deref under a malicious/manipulated server reply: an optional attribute assumed present "
     "in the RPC response is absent, dereferenced without a check")),
  ("net/rxrpc","teknik"): _j(_tc("stress_point","CWE-787",
     "OOB-write in rxrpc packet parsing: a length/offset field in an incoming ACK/DATA packet is trusted, "
     "letting a copy overflow a per-call buffer")),
}


def record(defter_path: str = DEFTER_YOLU_DEFAULT) -> tuple:
    """Load notebook, run the recorded operator on the 20 surfaces (exposure-blind), emit (provenance), save."""
    defter = OngoruDefteri.load(defter_path)
    backend = RecordedBackend(RECORDED)
    ctxs = {c.surface_id: c for c in veri_contexts()}
    cands = []
    for sid, _tier in TARGETS:
        cands.extend(run_operator(ctxs[sid], backend, ctxs[sid].tier))
    rep = emit_batch(defter, cands, CREATED_TS, provenance=PROVENANCE)
    defter.save(defter_path)
    return defter, rep


if __name__ == "__main__":
    d, rep = record()
    print("PILOT:", rep["counts"])
