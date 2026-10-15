"""
veri/kaynaklar/ — REAL source implementations (Pass-2). Each implements one of the two roles.

Data path: TIEFENRISS_DATA_DIR env (default /tmp/t4census — real kernel-CVE-git clone from the T4 workflow
+ NVD-CWE-join + syzbot). Status is MECHANICAL (from source); derivation is marked where it happens; no fabrication.

(Folder still named `kaynaklar/` — rename to `sources/` deferred to the folder-rename turn.)
"""
import os

DATA_DIR = os.environ.get("TIEFENRISS_DATA_DIR", "/tmp/t4census")
