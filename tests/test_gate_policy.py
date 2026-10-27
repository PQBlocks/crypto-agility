"""
Tests for feature 4 ci_gate.py — CI/CD Gate integration.

Covered edge cases:
  E14  PR diff with no crypto changes → gate passes
  E15  PR diff introduces Grade F  → gate fails (regression firewall)
  Absolute score failure: CARS < min_cars
  Absolute score pass:     CARS >= min_cars
"""
import json
import os
import tempfile
from pathlib import Path

import pytest

from pqblocks_agility.cbom import CBOM, CBOMComponent, parse_cbom
from pqblocks_agility.cars_scoring import score_cbom
from pqblocks_agility.ci_gate import evaluate_gate


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cbom(components):
    return CBOM(components=components)


def _make_cbom_above_threshold():
    """Four assets from spec §3.3: CARS=47.5, below 56.0."""
    components = [
        CBOMComponent("0", "ML-KEM-768", "1.0", "ML-KEM-768", "A", 1.0, "config.yaml:3", False),
        CBOMComponent("1", "RSA-2048", "1.0", "RSA-2048", "F", 0.0, "crypto.py:42", True),
        CBOMComponent("2", "AES-256-GCM", "1.0", "AES-256-GCM", "C", 0.6, "config.yaml:7", False),
        CBOMComponent("3", "ECDH-P256", "1.0", "ECDH-P256", "F", 0.0, "legacy.py:15", True),
    ]
    return CBOM(components=components)


def _make_cbom_below_threshold():
    """Single Grade-F asset: CARS=0.0, below 56.0."""
    components = [
        CBOMComponent("0", "RSA-2048", "1.0", "RSA-2048", "F", 0.0, "crypto.py:1", True),
    ]
    return CBOM(components=components)


# ---------------------------------------------------------------------------
# E14 — PR diff with no crypto changes → gate passes
# ---------------------------------------------------------------------------

class TestNoCryptoDiff:
    def test_diff_without_crypto_changes_passes(self):
        """E14: diff touching only non-crypto files must not trigger regression."""
        cbom = _make_cbom_above_threshold()
        diff = """\
diff --git a/README.md b/README.md
index abc..def 100644
--- a/README.md
+++ b/README.md
@@ -1,3 +1,4 @@
 Line 1
+New documentation line
 Line 2
 Line 3
"""
        result = evaluate_gate(cbom, min_cars=0.0, diff=diff, fail_on_regression=True,
                               allow_disallowed=True)
        assert result["exit_code"] == 0
        assert result["passed"] is True
        assert result["regression_detected"] is False
        assert len(result["regression_reasons"]) == 0


# ---------------------------------------------------------------------------
# E15 — PR diff introduces Grade F → gate fails
# ---------------------------------------------------------------------------

class TestRegressionFirewall:
    def test_diff_introducing_grade_f_fails(self):
        """E15: diff adding a Grade-F location triggers the regression firewall."""
        cbom = _make_cbom_above_threshold()
        diff = """\
diff --git a/crypto.py b/crypto.py
index 123..456 100644
--- a/crypto.py
+++ b/crypto.py
@@ -40,6 +40,8 @@ def legacy_rsa():
     # existing code
+    key = b"hardcoded-rsa-key-material-here----"
+    return rsa_encrypt(data, key)
"""
        result = evaluate_gate(cbom, min_cars=0.0, diff=diff, fail_on_regression=True)
        assert result["exit_code"] == 1
        assert result["passed"] is False
        assert result["regression_detected"] is True
        assert len(result["regression_reasons"]) > 0


# ---------------------------------------------------------------------------
# Absolute score failure / pass
# ---------------------------------------------------------------------------

class TestAbsoluteScore:
    def test_cars_below_threshold_fails(self):
        cbom = _make_cbom_below_threshold()
        result = evaluate_gate(cbom, min_cars=56.0)
        assert result["exit_code"] == 1
        assert result["passed"] is False
        assert result["cars_score"] == 25.0  # d3 = 0: the only asset is vulnerable code
        assert "below threshold" in " ".join(result["reasons"])

    def test_cars_above_threshold_passes(self):
        cbom = _make_cbom_above_threshold()
        result = evaluate_gate(cbom, min_cars=10.0, allow_disallowed=True)
        assert result["exit_code"] == 0
        assert result["passed"] is True


# ---------------------------------------------------------------------------
# Empty diff
# ---------------------------------------------------------------------------

class TestEmptyDiff:
    def test_empty_diff_never_triggers_regression(self):
        cbom = _make_cbom_above_threshold()
        result = evaluate_gate(cbom, min_cars=0.0, diff="", fail_on_regression=True)
        assert result["regression_detected"] is False
        assert len(result["regression_reasons"]) == 0


# ---------------------------------------------------------------------------
# SARIF output
# ---------------------------------------------------------------------------

class TestSarifOutput:
    def test_sarif_written_to_file(self):
        cbom = _make_cbom_above_threshold()
        with tempfile.TemporaryDirectory() as tmp:
            sarif_path = os.path.join(tmp, "agility.sarif")
            result = evaluate_gate(cbom, min_cars=0.0, sarif_out=sarif_path)
            assert os.path.exists(sarif_path)
            with open(sarif_path, "r", encoding="utf-8") as fh:
                sarif = json.load(fh)
            assert sarif["version"] == "2.1.0"
            assert "runs" in sarif
            assert len(sarif["runs"]) == 1
            assert sarif["runs"][0]["tool"]["driver"]["name"] == "pqblocks-agility"


# ---------------------------------------------------------------------------
# JSON summary output
# ---------------------------------------------------------------------------

class TestJsonOutput:
    def test_json_summary_written_to_file(self):
        cbom = _make_cbom_above_threshold()
        with tempfile.TemporaryDirectory() as tmp:
            json_path = os.path.join(tmp, "summary.json")
            result = evaluate_gate(cbom, min_cars=0.0, json_out=json_path)
            assert os.path.exists(json_path)
            with open(json_path, "r", encoding="utf-8") as fh:
                summary = json.load(fh)
            assert "cars_score" in summary
            assert "tier" in summary
            assert "passed" in summary
            assert "reasons" in summary
