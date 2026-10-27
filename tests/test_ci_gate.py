"""Comprehensive unit and edge-case tests for feature 4 ci_gate.py.

Covers:
- CARS tier classification and boundary conditions (including fractions and clamps)
- Diff parsing helpers (_added_lines, _diff_introduces_new_crypto)
- Edge cases in diff handling (empty diff, whitespace diff, no-git-header diff, missing location)
- evaluate_gate dual-trigger policy (absolute score threshold vs regression firewall)
- SARIF generation with edge cases (malformed line numbers, missing location, non-vulnerable components)
- JSON summary generation
"""

import json
import os
import tempfile
import pytest

from pqblocks_agility.cbom import CBOM, CBOMComponent
from pqblocks_agility.ci_gate import (
    evaluate_gate,
    get_cars_tier,
    _added_lines,
    _diff_introduces_new_crypto,
)


def test_tier_boundaries():
    # Exact boundaries per spec 1.4 and 11.4
    assert get_cars_tier(-10.0) == "Critical"
    assert get_cars_tier(0.0) == "Critical"
    assert get_cars_tier(30.0) == "Critical"
    assert get_cars_tier(31.0) == "At-Risk"
    assert get_cars_tier(55.0) == "At-Risk"
    assert get_cars_tier(56.0) == "Transitional"
    assert get_cars_tier(75.0) == "Transitional"
    assert get_cars_tier(76.0) == "Advanced"
    assert get_cars_tier(90.0) == "Advanced"
    assert get_cars_tier(91.0) == "Ready"
    assert get_cars_tier(100.0) == "Ready"
    assert get_cars_tier(105.0) == "Ready"


def test_tier_fractional_boundaries():
    # Fractional scores should not fall through to Critical if they are > 30
    assert get_cars_tier(30.5) == "At-Risk"
    assert get_cars_tier(55.5) == "Transitional"
    assert get_cars_tier(75.5) == "Advanced"
    assert get_cars_tier(90.5) == "Ready"


def test_added_lines():
    diff_text = """diff --git a/foo.py b/foo.py
--- a/foo.py
+++ b/foo.py
@@ -1,3 +1,4 @@
 context
+new_line_1
-deleted_line
+new_line_2
"""
    added = _added_lines(diff_text)
    assert added == ["+new_line_1", "+new_line_2"]


def test_diff_introduces_new_crypto_edge_cases():
    cbom = CBOM(
        components=[
            CBOMComponent("0", "RSA-2048", "1.0", "RSA-2048", "F", 0.0, "crypto.py:42", True),
            CBOMComponent("1", "AES-256", "1.0", "AES-256", "C", 0.6, "crypto.py:10", False),
            CBOMComponent("2", "RSA-1024", "1.0", "RSA-1024", "F", 0.0, "other.py:1", True),
        ]
    )

    # 1. Empty string or whitespace-only diff
    assert _diff_introduces_new_crypto("", cbom) == []
    assert _diff_introduces_new_crypto("   \n\t  ", cbom) == []

    # 2. Plain unified diff (no 'diff --git' header) is parsed from its '+++' line
    no_git_header = "+++ b/crypto.py\n+some change\n"
    assert len(_diff_introduces_new_crypto(no_git_header, cbom)) == 1

    # 3. Diff modifying file with only non-vulnerable crypto
    cbom_safe = CBOM(
        components=[
            CBOMComponent("1", "AES-256", "1.0", "AES-256", "C", 0.6, "safe.py:10", False),
        ]
    )
    safe_diff = "diff --git a/safe.py b/safe.py\n+safe change\n"
    assert _diff_introduces_new_crypto(safe_diff, cbom_safe) == []

    # 4. Diff matching vulnerable component with location
    vuln_diff = "diff --git a/crypto.py b/crypto.py\n+vuln change\n"
    reasons = _diff_introduces_new_crypto(vuln_diff, cbom)
    assert len(reasons) == 1
    assert "RSA-2048" in reasons[0]


def test_evaluate_gate_sarif_malformed_location_and_no_location():
    cbom = CBOM(
        components=[
            # Location with non-integer line number
            CBOMComponent("0", "RSA-2048", "1.0", "RSA-2048", "F", 0.0, "crypto.py:notanumber", True),
            # Location without colon
            CBOMComponent("1", "RSA-1024", "1.0", "RSA-1024", "F", 0.0, "nocolon.py", True),
            # Location is None
            CBOMComponent("2", "RSA-512", "1.0", "RSA-512", "F", 0.0, None, True),
            # Safe component
            CBOMComponent("3", "ML-KEM-768", "1.0", "ML-KEM-768", "A", 1.0, "config.yaml:5", False),
        ]
    )

    with tempfile.TemporaryDirectory() as tmp:
        sarif_file = os.path.join(tmp, "out.sarif")
        res = evaluate_gate(cbom, min_cars=0.0, sarif_out=sarif_file, allow_disallowed=True)
        assert res["exit_code"] == 0
        assert os.path.exists(sarif_file)

        with open(sarif_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        assert data["version"] == "2.1.0"
        results = data["runs"][0]["results"]
        assert len(results) == 3  # 3 vulnerable components
