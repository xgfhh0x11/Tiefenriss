"""
montaj.py — A2.4 ATTACK-PATH ASSEMBLY + path-registry. DETERMINISTIC (Pass-1).

PRINCIPLE: GATE the atoms, PRESENT the path. The notebook = atomic gate-able predictions; the PATH = a separate registry,
REFERENCING prediction-ids. A path does "not realize" → its annotation is only as strong as the WEAKEST unconfirmed ATOM
(node OR edge; transitions ARE counted).

In Pass-1 the chain-logic comes from the STUB (path-spec = a sequence of atom-keys); in Pass-2 the LLM produces it with
exploit-primitive-logic. Assembly: builds a path from admitted atoms, does NOT count an INCOMPLETE path (one atom rejected)
as COMPLETE — a path with an untestable atom is NOT PRESENTED.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .ongoru_defteri import Realization

# weakest-atom ordering: low = weak. A path is only as strong as its weakest atom.
_STRENGTH = {Realization.CURUDU: 0, Realization.LAPSED: 1, Realization.BEKLIYOR: 2, Realization.GERCEKLESTI: 3}


@dataclass
class Path:
    path_id: str
    direction: str
    atom_pred_ids: list[str]          # ordered atoms (node+edge) — notebook prediction-ids
    complete: bool                    # did all its atoms pass the boundary
    missing_atom_keys: list[str] = field(default_factory=list)   # rejected atoms (if incomplete)


class PathRegistry:
    def __init__(self):
        self._paths: list[Path] = []

    def add(self, p: Path):
        self._paths.append(p)

    def complete_paths(self) -> list[Path]:
        return [p for p in self._paths if p.complete]

    def __len__(self):
        return len(self._paths)


def assemble(path_specs: list[dict], admitted_map: dict[str, str]) -> PathRegistry:
    """
    path_specs: [{path_id, direction, atom_keys:[key,...]}]. If an atom_key is not in admitted_map (rejected) →
    the path is INCOMPLETE (complete=False, that atom is not presented). All admitted → a complete path (pred_id referenced).
    """
    reg = PathRegistry()
    for spec in path_specs:
        keys = spec["atom_keys"]
        missing = [k for k in keys if k not in admitted_map]
        pred_ids = [admitted_map[k] for k in keys if k in admitted_map]
        reg.add(Path(
            path_id=spec["path_id"], direction=spec.get("direction", "ileri"),
            atom_pred_ids=pred_ids, complete=(len(missing) == 0), missing_atom_keys=missing,
        ))
    return reg


def weakest_atom(path: Path, defter) -> dict | None:
    """
    Path-annotation: the weakest unconfirmed atom (node OR EDGE — transitions included).
    Returns {pred_id, pred_type, realization} or None (no atom).
    """
    by_id = {o.pred_id: o for o in defter._kayitlar}
    atoms = [by_id[pid] for pid in path.atom_pred_ids if pid in by_id]
    if not atoms:
        return None
    w = min(atoms, key=lambda o: _STRENGTH.get(o.realization, 2))
    return {"pred_id": w.pred_id, "pred_type": w.pred_type.value, "realization": w.realization.value}
