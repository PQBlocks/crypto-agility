"""Tests for feature 5 sarif_export.py — SARIF 2.1.0 export of CARS results.

Covers spec section 6: valid SARIF schema, D1-D5 rules, property bag metrics,
individual results mapped to rule IDs, edge cases (empty CBOM, Grade-F, missing locations).
"""

import json
import os
import tempfile
import pytest

from pqblocks_agility.cbom import CBOM, CBOMComponent
from pqblocks_agility.sarif_export import (
    export_sarif,
    build_sarif,
    CARS_RULE_IDS,
    CARS_TOOL_NAME,
    CARS_TOOL_VERSION,
    SARIF_VERSION,
)


def _make_cbom(components):
    comps = []
    for i, (grade, qv, loc) in enumerate(components):
        algo_map = {
            "A": "ML-KEM-768", "B": "X25519MLKEM768",
            "C": "AES-256-GCM", "D": "RSA-3072", "F": "RSA-2048",
        }
        grade_value = {"A": 1.0, "B": 0.85, "C": 0.6, "D": 0.3, "F": 0.0}[grade]
        comps.append(
            CBOMComponent(
                component_id=str(i), name=algo_map.get(grade, "UNKNOWN"),
                version="1.0", algorithm=algo_map.get(grade, "UNKNOWN"),
                grade=grade, grade_value=grade_value,
                location=loc, quantum_vulnerable=qv,
            )
        )
    return CBOM(components=comps)


def test_sarif_version():
    cbom = CBOM(components=[])
    sarif = build_sarif(cbom, 0.0, {"d1": 0, "d2": 0, "d3": 0, "d4": 0, "d5": 0}, "Critical")
    assert sarif["version"] == SARIF_VERSION


def test_sarif_tool_driver():
    cbom = CBOM(components=[])
    sarif = build_sarif(cbom, 0.0, {"d1": 0, "d2": 0, "d3": 0, "d4": 0, "d5": 0}, "Critical")
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == CARS_TOOL_NAME
    assert driver["version"] == CARS_TOOL_VERSION


def test_sarif_has_rules():
    cbom = CBOM(components=[])
    sarif = build_sarif(cbom, 0.0, {"d1": 0, "d2": 0, "d3": 0, "d4": 0, "d5": 0}, "Critical")
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == CARS_RULE_IDS


def test_sarif_rule_descriptions():
    cbom = CBOM(components=[])
    sarif = build_sarif(cbom, 0.0, {"d1": 0, "d2": 0, "d3": 0, "d4": 0, "d5": 0}, "Critical")
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    for rule in rules:
        assert "shortDescription" in rule
        assert "text" in rule["shortDescription"]


def test_sarif_properties_bag():
    cbom = CBOM(components=[])
    sarif = build_sarif(cbom, 47.5, {"d1": 0.5, "d2": 0.4, "d3": 0.5, "d4": 0.5, "d5": 0.5}, "At-Risk")
    props = sarif["runs"][0]["properties"]
    for k in ("CARS-D1", "CARS-D2", "CARS-D3", "CARS-D4", "CARS-D5", "CARSComposite", "CARS_Tier", "scoring_mode"):
        assert k in props
    assert props["CARSComposite"] == 47.5
    assert props["CARS_Tier"] == "At-Risk"
    assert props["scoring_mode"] == "scenario"


def test_sarif_dimension_values():
    dims = {"d1": 0.50, "d2": 0.40, "d3": 0.50, "d4": 0.50, "d5": 0.50}
    cbom = CBOM(components=[])
    sarif = build_sarif(cbom, 47.5, dims, "At-Risk")
    props = sarif["runs"][0]["properties"]
    for i in range(1, 6):
        assert props[f"CARS-D{i}"] == dims[f"d{i}"]

    # Also verify dimensions passed with CARS-D* keys
    dims_cars = {"CARS-D1": 0.50, "CARS-D2": 0.40, "CARS-D3": 0.50, "CARS-D4": 0.50, "CARS-D5": 0.50}
    sarif2 = build_sarif(cbom, 47.5, dims_cars, "At-Risk")
    props2 = sarif2["runs"][0]["properties"]
    for k in ("CARS-D1", "CARS-D2", "CARS-D3", "CARS-D4", "CARS-D5"):
        assert props2[k] == dims_cars[k]


def test_sarif_results_empty_cbom():
    cbom = CBOM(components=[])
    sarif = build_sarif(cbom, 0.0, {"d1": 0, "d2": 0, "d3": 0, "d4": 0, "d5": 0}, "Critical")
    assert sarif["runs"][0]["results"] == []


def test_sarif_results_grade_f_findings():
    cbom = _make_cbom([("F", True, "crypto.py:42"), ("A", False, "config.yaml:3"), ("F", True, "legacy.py:15")])
    sarif = build_sarif(cbom, 0.0, {"d1": 0.5, "d2": 0.0, "d3": 0.5, "d4": 0.5, "d5": 0.5}, "Critical")
    results = sarif["runs"][0]["results"]
    assert len(results) == 2
    for r in results:
        assert r["ruleId"] == "CARS-D2"
        assert r["level"] == "warning"


def test_sarif_results_with_locations():
    cbom = _make_cbom([("F", True, "crypto.py:42")])
    sarif = build_sarif(cbom, 0.0, {"d1": 0, "d2": 0, "d3": 0, "d4": 0, "d5": 0}, "Critical")
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    loc = results[0]["locations"][0]
    assert loc["physicalLocation"]["artifactLocation"]["uri"] == "crypto.py"
    assert loc["physicalLocation"]["region"]["startLine"] == 42


def test_sarif_results_missing_location():
    cbom = _make_cbom([("F", True, None)])
    sarif = build_sarif(cbom, 0.0, {"d1": 0, "d2": 0, "d3": 0, "d4": 0, "d5": 0}, "Critical")
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    assert "locations" not in results[0]


def test_sarif_results_noninteger_line():
    cbom = _make_cbom([("F", True, "crypto.py:notanumber")])
    sarif = build_sarif(cbom, 0.0, {"d1": 0, "d2": 0, "d3": 0, "d4": 0, "d5": 0}, "Critical")
    results = sarif["runs"][0]["results"]
    assert len(results) == 1


def test_sarif_results_message_content():
    cbom = _make_cbom([("F", True, "crypto.py:42")])
    sarif = build_sarif(cbom, 0.0, {"d1": 0, "d2": 0, "d3": 0, "d4": 0, "d5": 0}, "Critical")
    results = sarif["runs"][0]["results"]
    assert "Grade F" in results[0]["message"]["text"]
    assert "RSA-2048" in results[0]["message"]["text"]


def test_export_sarif_writes_file():
    cbom = _make_cbom([("F", True, "crypto.py:42")])
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "out.sarif")
        export_sarif(cbom, 0.0, {"d1": 0, "d2": 0, "d3": 0, "d4": 0, "d5": 0}, "Critical", path)
        assert os.path.exists(path)
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1


def test_export_sarif_roundtrip():
    cbom = _make_cbom([("F", True, "crypto.py:42"), ("C", False, "config.yaml:7")])
    sarif = build_sarif(cbom, 25.0, {"d1": 0.5, "d2": 0.5, "d3": 0.5, "d4": 0.5, "d5": 0.5}, "Critical")
    parsed = json.loads(json.dumps(sarif))
    assert parsed["runs"][0]["properties"]["CARSComposite"] == 25.0


def test_export_sarif_independent_runs():
    cbom = _make_cbom([("F", True, "crypto.py:42")])
    sarif1 = build_sarif(cbom, 0.0, {"d1": 0, "d2": 0, "d3": 0, "d4": 0, "d5": 0}, "Critical")
    sarif2 = build_sarif(cbom, 100.0, {"d1": 1, "d2": 1, "d3": 1, "d4": 1, "d5": 1}, "Ready")
    assert sarif1["runs"][0]["properties"]["CARSComposite"] == 0.0
    assert sarif2["runs"][0]["properties"]["CARSComposite"] == 100.0


def test_sarif_empty_dimensions():
    cbom = CBOM(components=[])
    sarif = build_sarif(cbom, 0.0, {"d1": 0, "d2": 0, "d3": 0, "d4": 0, "d5": 0}, "Critical")
    props = sarif["runs"][0]["properties"]
    for k in ("CARS-D1", "CARS-D2", "CARS-D3", "CARS-D4", "CARS-D5"):
        assert props[k] == 0.0


def test_sarif_all_grade_a():
    cbom = _make_cbom([("A", False, "config.yaml:3")])
    sarif = build_sarif(cbom, 100.0, {"d1": 1, "d2": 1, "d3": 1, "d4": 1, "d5": 1}, "Ready")
    assert sarif["runs"][0]["results"] == []


def test_sarif_different_tiers():
    for tier in ("Critical", "At-Risk", "Transitional", "Advanced", "Ready"):
        cbom = CBOM(components=[])
        sarif = build_sarif(cbom, 0.0, {"d1": 0, "d2": 0, "d3": 0, "d4": 0, "d5": 0}, tier)
        assert sarif["runs"][0]["properties"]["CARS_Tier"] == tier


def test_sarif_results_only_vulnerable():
    cbom = _make_cbom([("A", False, "config.yaml:1"), ("B", False, "config.yaml:2"), ("C", False, "config.yaml:3")])
    sarif = build_sarif(cbom, 80.0, {"d1": 1, "d2": 1, "d3": 1, "d4": 1, "d5": 1}, "Advanced")
    assert sarif["runs"][0]["results"] == []


def test_sarif_module_alias():
    import pqblocks_agility.sarif as sarif_mod
    assert sarif_mod.build_sarif is build_sarif
    assert sarif_mod.export_sarif is export_sarif
    assert sarif_mod.SARIF_VERSION == SARIF_VERSION
    assert sarif_mod.CARS_TOOL_NAME == CARS_TOOL_NAME
    assert sarif_mod.CARS_TOOL_VERSION == CARS_TOOL_VERSION
    assert sarif_mod.CARS_RULE_IDS == CARS_RULE_IDS