"""SARIF 2.1.0 export (feature 5).

Produces SARIF 2.1.0 JSON from CARS scoring results per spec section 6:
- Dimension sub-scores as custom property bag metrics on the run object
- Individual informational results mapped to rule IDs CARS-D1 through CARS-D5
- One result per Grade-F / quantum_vulnerable component, ruleId CARS-D2

Derivation is ideas-only from the spec's openly published schema.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from pqblocks_agility.cbom import CBOM

SARIF_VERSION = "2.1.0"
CARS_TOOL_NAME = "pqblocks-agility"
CARS_TOOL_VERSION = "0.1.0"
CARS_RULE_IDS = ["CARS-D1", "CARS-D2", "CARS-D3", "CARS-D4", "CARS-D5"]

_DIMENSION_KEYS = ("d1", "d2", "d3", "d4", "d5")


def build_sarif(
    cbom: CBOM,
    cars_score: float,
    dimensions: Dict[str, float],
    tier: str,
) -> Dict[str, Any]:
    """Build a SARIF 2.1.0 document from CARS scoring results.

    Args:
        cbom: Validated CBOM dataclass.
        cars_score: Composite CARS score (0-100).
        dimensions: Dict with keys d1..d5, each in [0, 1].
        tier: Tier string from get_cars_tier().

    Returns:
        Dict conforming to the SARIF 2.1.0 schema per spec 6.2.
    """
    properties: Dict[str, Any] = {
        f"CARS-D{i}": dimensions.get(f"d{i}", dimensions.get(f"CARS-D{i}", 0.0))
        for i in range(1, 6)
    }
    properties["CARSComposite"] = cars_score
    properties["CARS_Tier"] = tier
    properties["scoring_mode"] = "scenario"

    sarif: Dict[str, Any] = {
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": CARS_TOOL_NAME,
                        "version": CARS_TOOL_VERSION,
                        "rules": [
                            {"id": rid, "shortDescription": {"text": _rule_text(rid)}}
                            for rid in CARS_RULE_IDS
                        ],
                    }
                },
                "properties": properties,
                "results": _build_results(cbom),
            }
        ],
    }
    return sarif


def _rule_text(rule_id: str) -> str:
    mapping = {
        "CARS-D1": "Inventory Completeness",
        "CARS-D2": "Algorithm Compliance",
        "CARS-D3": "Architectural Decoupling",
        "CARS-D4": "Toolchain Readiness",
        "CARS-D5": "Governance & Compliance",
    }
    return mapping.get(rule_id, rule_id)


def _build_results(cbom: CBOM) -> list:
    """Build the results array: one per Grade-F or quantum_vulnerable component."""
    results: list = []
    for comp in cbom.components:
        if comp.grade != "F" and not comp.quantum_vulnerable:
            continue
        entry: Dict[str, Any] = {
            "ruleId": "CARS-D2",
            "level": "warning",
            "message": {"text": f"Grade {comp.grade} finding: {comp.algorithm} at {comp.location or 'unknown'}"},
        }
        if comp.location:
            file_part = comp.location.split(":")[0]
            region: Dict[str, Any] = {}
            if ":" in comp.location:
                try:
                    region["startLine"] = int(comp.location.split(":")[1])
                except ValueError:
                    pass
            loc_block: Dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {"uri": file_part},
                    **({"region": region} if region else {}),
                }
            }
            entry["locations"] = [loc_block]
        results.append(entry)
    return results


def export_sarif(
    cbom: CBOM,
    cars_score: float,
    dimensions: Dict[str, float],
    tier: str,
    path: str,
) -> None:
    """Write a SARIF 2.1.0 document to *path*.

    Args:
        cbom: Validated CBOM dataclass.
        cars_score: Composite CARS score.
        dimensions: Dict with keys d1..d5.
        tier: Tier string.
        path: Output file path.
    """
    sarif = build_sarif(cbom, cars_score, dimensions, tier)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2)