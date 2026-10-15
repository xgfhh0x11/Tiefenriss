"""
core_bridge.py — the SINGLE point that connects the core to the adapter.

The core now lives in the `Tiefenriss/cekirdek/` package (sealed, sibling layer).
The old directory-name-independence shim was REMOVED (it was technical debt) — plain import.

One-way dependency: the adapter imports the core, the core is unaware of the adapter.
Running: from the project root (Tiefenriss/) `python3 -m adapter.<module>` — the root is on sys.path,
`cekirdek` and `adapter` resolve as sibling top-level packages.
"""
from cekirdek.model import ElementProfile, GraphPosition, Signal, DepthDecision
from cekirdek.core import CoreParams, evaluate

__all__ = [
    "ElementProfile", "GraphPosition", "Signal", "DepthDecision",
    "CoreParams", "evaluate",
]
