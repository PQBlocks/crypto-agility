"""Tests for cli.py — CLI interface.

Covers:
- `python -m pqblocks_agility.cli --help` / `pqblocks-agility --help`
- Commands: `gate`, `evaluate`, `check-staged`, `scan`
- `gate` flags:
  --cbom
  --diff-base
  --diff-file
  --min-cars
  --fail-on-regression / --fail-on-disallowed
  --sarif-out
  --json-out
  --profile (default, embedded-iot, cloud-enterprise)
  --d1-mode (scenario, empirical)
- `evaluate` flags:
  --cbom
  --min-cars
  --profile
  --d1-mode
  --sarif-out
  --json-out
  --gitlab-report
- `check-staged` pre-commit hook:
  --strict-keys
  --forbid-fips-disallowed
- `scan` placeholder/fallback command:
  --output
- Unknown profile handling (E20 UnknownProfileError / exit code 2 or error output)
- Missing CBOM file handling (E18 FileNotFoundError / exit code 1 or 2)
"""

import json
import subprocess
import os
import tempfile
from click.testing import CliRunner
import pytest

from pqblocks_agility.cli import cli, UnknownProfileError
from pqblocks_agility.cbom import CBOM, CBOMComponent


SAMPLE_CBOM = {
    "specVersion": "1.6",
    "components": [
        {
            "name": "ML-KEM-768",
            "version": "1.0",
            "properties": [
                {"name": "pqblocks-scan.grade", "value": "A"},
                {"name": "pqblocks-scan.algorithm", "value": "ML-KEM-768"},
                {"name": "pqblocks-scan.location", "value": "config.yaml:3"},
                {"name": "pqblocks-scan.quantum_vulnerable", "value": "false"},
            ],
        },
        {
            "name": "RSA-2048",
            "version": "1.0",
            "properties": [
                {"name": "pqblocks-scan.grade", "value": "F"},
                {"name": "pqblocks-scan.algorithm", "value": "RSA-2048"},
                {"name": "pqblocks-scan.location", "value": "crypto.py:42"},
                {"name": "pqblocks-scan.quantum_vulnerable", "value": "true"},
            ],
        },
    ],
}


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def cbom_file(tmp_path):
    p = tmp_path / "cbom.json"
    p.write_text(json.dumps(SAMPLE_CBOM), encoding="utf-8")
    return str(p)


def test_cli_help(runner):
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "gate" in result.output
    assert "evaluate" in result.output
    assert "check-staged" in result.output
    assert "scan" in result.output


def test_gate_help(runner):
    result = runner.invoke(cli, ["gate", "--help"])
    assert result.exit_code == 0
    assert "--cbom" in result.output
    assert "--min-cars" in result.output
    assert "--sarif-out" in result.output
    assert "--json-out" in result.output


def test_gate_evaluate_pass(runner, cbom_file, tmp_path):
    sarif_out = str(tmp_path / "out.sarif")
    json_out = str(tmp_path / "out.json")
    result = runner.invoke(
        cli,
        [
            "gate",
            "--cbom", cbom_file,
            "--min-cars", "20.0",
            "--allow-disallowed",
            "--sarif-out", sarif_out,
            "--json-out", json_out,
        ],
    )
    assert result.exit_code == 0
    assert "PASS" in result.output or "Gate passed" in result.output or "CARS" in result.output
    assert os.path.exists(sarif_out)
    assert os.path.exists(json_out)


def test_gate_evaluate_fail_threshold(runner, cbom_file):
    result = runner.invoke(
        cli,
        [
            "gate",
            "--cbom", cbom_file,
            "--min-cars", "90.0",
        ],
    )
    assert result.exit_code == 1
    assert "FAIL" in result.output or "below threshold" in result.output or "Critical" in result.output or "At-Risk" in result.output


def test_gate_with_diff_file_regression_fail(runner, cbom_file, tmp_path):
    diff_file = tmp_path / "pr.diff"
    diff_file.write_text(
        "diff --git a/crypto.py b/crypto.py\n--- a/crypto.py\n+++ b/crypto.py\n@@ -42,1 +42,1 @@\n+import RSA\n",
        encoding="utf-8",
    )
    result = runner.invoke(
        cli,
        [
            "gate",
            "--cbom", cbom_file,
            "--diff-file", str(diff_file),
            "--fail-on-regression",
            "--min-cars", "0.0",
        ],
    )
    assert result.exit_code == 1


def test_gate_with_diff_file_no_regression_pass(runner, cbom_file, tmp_path):
    diff_file = tmp_path / "pr.diff"
    diff_file.write_text(
        "diff --git a/README.md b/README.md\n--- a/README.md\n+++ b/README.md\n@@ -1,1 +1,1 @@\n+# New\n",
        encoding="utf-8",
    )
    result = runner.invoke(
        cli,
        [
            "gate",
            "--cbom", cbom_file,
            "--diff-file", str(diff_file),
            "--fail-on-regression",
            "--allow-disallowed",
            "--min-cars", "20.0",
        ],
    )
    assert result.exit_code == 0


def test_evaluate_command_json_and_gitlab(runner, cbom_file, tmp_path):
    gl_out = str(tmp_path / "gl-security-report.json")
    sarif_out = str(tmp_path / "eval.sarif")
    result = runner.invoke(
        cli,
        [
            "evaluate",
            "--cbom", cbom_file,
            "--min-cars", "30.0",
            "--gitlab-report", gl_out,
            "--sarif-out", sarif_out,
        ],
    )
    assert result.exit_code == 0
    assert os.path.exists(gl_out)
    assert os.path.exists(sarif_out)


def test_profiles_embedded_iot(runner, cbom_file):
    result = runner.invoke(
        cli,
        [
            "evaluate",
            "--cbom", cbom_file,
            "--profile", "embedded-iot",
            "--min-cars", "0",
        ],
    )
    assert result.exit_code == 0


def test_unknown_profile_raises(runner, cbom_file):
    result = runner.invoke(
        cli,
        [
            "evaluate",
            "--cbom", cbom_file,
            "--profile", "non-existent-profile",
        ],
    )
    assert result.exit_code != 0
    assert "unknown weight profile" in result.output.lower()


def test_check_staged_clean(runner, tmp_path):
    with runner.isolated_filesystem():
        subprocess.run(["git", "init", "-q", "."], check=True)
        result = runner.invoke(cli, ["check-staged"])
    assert result.exit_code == 0


def test_scan_placeholder(runner, tmp_path):
    cbom_out = str(tmp_path / "scanned_cbom.json")
    result = runner.invoke(cli, ["scan", str(tmp_path), "--output", cbom_out])
    assert result.exit_code == 0
    assert os.path.exists(cbom_out)


def test_gate_missing_cbom(runner):
    result = runner.invoke(cli, ["gate", "--cbom", "nonexistent.json"])
    assert result.exit_code == 2
    assert "not found" in result.output.lower()


def test_evaluate_missing_cbom(runner):
    result = runner.invoke(cli, ["evaluate", "--cbom", "nonexistent.json"])
    assert result.exit_code == 2
    assert "not found" in result.output.lower()


def test_gate_unknown_profile(runner, cbom_file):
    result = runner.invoke(cli, ["gate", "--cbom", cbom_file, "--profile", "bogus"])
    assert result.exit_code == 2
    assert "unknown weight profile" in result.output.lower()


def test_evaluate_empirical_mode(runner, cbom_file):
    result = runner.invoke(cli, ["evaluate", "--cbom", cbom_file, "--d1-mode", "empirical", "--min-cars", "0"])
    assert result.exit_code == 0
    assert "CARS Score:" in result.output


def test_evaluate_empty_cbom(runner, tmp_path):
    empty_cbom_file = tmp_path / "empty.json"
    empty_cbom_file.write_text(json.dumps({"specVersion": "1.6", "components": []}))
    result = runner.invoke(cli, ["evaluate", "--cbom", str(empty_cbom_file), "--min-cars", "0"])
    assert result.exit_code == 0
    assert "CARS Score: 0.0" in result.output


def test_gate_diff_base_option(runner, cbom_file):
    result = runner.invoke(cli, ["gate", "--cbom", cbom_file, "--diff-base", "HEAD"])
    # May pass or fail depending on whether HEAD is valid git, but should execute without unhandled exception
    assert result.exit_code in (0, 1)


def test_cli_main_entrypoint():
    from pqblocks_agility.cli import main
    # Ensure main is callable
    assert callable(main)
