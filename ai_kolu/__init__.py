"""
ai_kolu/ — Tiefenriss's 4th layer: AI ARM.

STATUS: NOT YET BEING BUILT. This package currently contains only `ongoru_defteri.py` (empty schema)
— the epistemic foundation that must be laid BEFORE the AI arm is built.

Architectural decisions (PRINCIPLE, sealed): `adapter/PoC_BULGULAR.md` §"AI KOLU MİMARİSİ" (İ1-İ9 + #Ç4).

Dependency direction (invariant): ai_kolu → adapter → cekirdek. Never the reverse.
ai_kolu does NOT WRITE to the Prozessfall DB; it keeps its own OUTPUT-store (prediction-notebook).
"""
