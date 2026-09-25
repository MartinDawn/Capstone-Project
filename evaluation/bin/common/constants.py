#!/usr/bin/env python3
"""Shared protocol constants for the conformance, cost, and legacy perf runners."""

from __future__ import annotations

# Legacy protocol revision. It still governs the conformance evidence and the historical perf (k6 load)
# runs, which must stay readable under the revision they were produced with.
PROTOCOL_ID = "BP-20260915-v3"

# Current protocol revision (docs/EVALUATION_PROTOCOL.md): sequential cost (E-COST), artifact/wire-byte measurement
# (E-ARTIFACT), and, as of BP-20260922-v6, the reinstated offered-load experiment (E-LOAD). E-LOAD
# final evidence stays additionally gated by the live isolation proof (BLK-004) and known prototype
# defects (BLK-013); see docs/EVALUATION_PROTOCOL.md section 3.4.
COST_PROTOCOL_ID = "BP-20260922-v6"

# Seed of the deterministic paired-block bootstrap and of the model-order rotation.
COST_SEED = 20260921

# Canonical configuration -> short runner alias.
MODEL_ALIASES = {"B0-C0": "b0", "B1-C0": "b1", "B1-C2": "b2"}

# Canonical configuration -> manage.ps1 / manage.sh baseline argument.
BASELINE_ALIASES = {"B0-C0": "b0", "B1-C0": "b1-classical", "B1-C2": "b1-pqc"}

# Evidence family roots. Each experiment writes only under its own root.
EVIDENCE_FAMILIES = ("conformance", "perf", "cost", "artifacts")

# Protocol revision that each family's configuration must declare. "perf" (E-LOAD) followed the legacy
# conformance revision while retired; reinstated under BP-20260922-v6 it now follows COST_PROTOCOL_ID,
# the same docs/EVALUATION_PROTOCOL.md revision that governs E-COST and E-ARTIFACT.
PROTOCOL_IDS_BY_FAMILY = {
    "conformance": PROTOCOL_ID,
    "perf": COST_PROTOCOL_ID,
    "cost": COST_PROTOCOL_ID,
    "artifacts": COST_PROTOCOL_ID,
}


def evidence_root(workspace, family: str):
    """Return evaluation/evidence/<family> for the given workspace."""
    if family not in EVIDENCE_FAMILIES:
        raise ValueError(f"Unknown evidence family: {family}")
    from pathlib import Path

    return Path(workspace) / "evaluation" / "evidence" / family
