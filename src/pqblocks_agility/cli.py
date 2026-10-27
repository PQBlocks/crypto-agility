"""Command-line interface for pqblocks-agility.

Provides the CLI commands per Spec §1.3, §5, §7.2:
- gate: Enforces CI/CD policy thresholds and regression firewall.
- evaluate: Computes CARS score, dimensions, and exports reports.
- check-staged: Pre-commit hook checking staged files for hardcoded keys and disallowed primitives.
- scan: Local/fallback scanner generating CycloneDX 1.6 CBOM.

Supports configurable parameters:
--min-cars: float threshold (default 56.0)
--profile: weight profile ('default', 'embedded-iot', 'cloud-enterprise')
--d1-mode: d1 estimation mode ('scenario', 'empirical')
--fail-on-regression / --fail-on-disallowed: regression firewall flag
--sarif-out: SARIF 2.1.0 report output path
--json-out: JSON summary report output path
--gitlab-report: GitLab container/dependency scanning report output path
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from typing import Any, Dict, Optional, Tuple

import click

from pqblocks_agility.cars_scoring import (  # noqa: F401  (re-exported for callers)
    WEIGHT_PROFILES,
    UnknownProfileError,
    compute_cars_score,
    get_profile_weights,
)
from pqblocks_agility.cbom import parse_cbom
from pqblocks_agility.ci_gate import evaluate_gate
from pqblocks_agility.decouple import has_hardcoded_key
from pqblocks_agility.sarif_export import export_sarif

# Exit codes: 0 pass, 1 policy failure, 2 usage / input error.
EXIT_POLICY = 1
EXIT_INPUT = 2


def run_gate_logic(
    cbom_path: str,
    min_cars: float = 56.0,
    diff_text: str = "",
    fail_on_regression: bool = False,
    profile: str = "default",
    d1_mode: str = "scenario",
    sarif_out: Optional[str] = None,
    json_out: Optional[str] = None,
    gitlab_out: Optional[str] = None,
    allow_disallowed: bool = False,
) -> Tuple[int, Dict[str, Any]]:
    """Parse the CBOM and run ci_gate.evaluate_gate, then write the requested reports."""
    cbom = parse_cbom(cbom_path)
    result = evaluate_gate(
        cbom, min_cars=min_cars, diff=diff_text, fail_on_regression=fail_on_regression,
        profile=profile, d1_mode=d1_mode, allow_disallowed=allow_disallowed,
    )
    result["profile"] = profile
    result["d1_mode"] = d1_mode
    cars_score, dimensions, tier = result["cars_score"], result["dimensions"], result["tier"]

    # Export SARIF
    if sarif_out:
        export_sarif(cbom, cars_score, dimensions, tier, sarif_out)

    # Export JSON summary
    if json_out:
        with open(json_out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)

    # Export GitLab report
    if gitlab_out:
        gl_report = {
            "version": "15.0.0",
            "vulnerabilities": [
                {
                    "id": comp.component_id,
                    "category": "crypto_agility",
                    "name": f"Vulnerable cryptographic primitive {comp.algorithm}",
                    "message": f"Primitive {comp.algorithm} (Grade {comp.grade}) located at {comp.location or 'unknown'}",
                    "severity": "High" if comp.grade == "F" else "Medium",
                    "location": {
                        "file": comp.location.split(":")[0] if comp.location else "unknown",
                        "line": int(comp.location.split(":")[1]) if (comp.location and ":" in comp.location and comp.location.split(":")[1].isdigit()) else 1,
                    },
                }
                for comp in cbom.components
                if comp.grade == "F" or comp.quantum_vulnerable
            ],
            "remediations": [],
        }
        with open(gitlab_out, "w", encoding="utf-8") as fh:
            json.dump(gl_report, fh, indent=2)

    return result["exit_code"], result


# ---------------------------------------------------------------------------
# Click CLI
# ---------------------------------------------------------------------------

def _fail(message: str, code: int = EXIT_INPUT):
    click.echo(f"Error: {message}", err=True)
    sys.exit(code)


def _threshold(ctx, param, value):
    if not (0.0 <= value <= 100.0):  # also rejects NaN
        raise click.BadParameter("must be a number between 0 and 100")
    return value


def _read_diff(diff_file: Optional[str], diff_base: Optional[str]) -> str:
    """Return the diff text, or exit 2: the regression firewall never runs on a missing diff."""
    if diff_file:
        try:
            with open(diff_file, encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError as exc:
            _fail(f"cannot read diff file {diff_file}: {exc.strerror}")
    if not diff_base:
        _fail("--fail-on-regression requires --diff-file or --diff-base")
    if diff_base.startswith("-"):
        _fail(f"invalid --diff-base {diff_base!r}")
    try:
        res = subprocess.run(["git", "diff", "--no-ext-diff", diff_base, "--"],
                             capture_output=True, text=True, check=False)
    except OSError as exc:
        _fail(f"git diff failed: {exc.strerror}")
    if res.returncode != 0:
        _fail(f"git diff {diff_base} failed: {res.stderr.strip()}")
    return res.stdout


def _run(**kwargs) -> Tuple[int, Dict[str, Any]]:
    """run_gate_logic with every input problem mapped to exit code 2."""
    try:
        return run_gate_logic(**kwargs)
    except (ValueError, OSError) as exc:  # parse/validation/profile/diff/IO errors
        _fail(str(exc))


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """pqblocks-agility: Post-Quantum Cryptographic Agility assessment and CI gate.

    Exit codes: 0 pass, 1 policy failure, 2 usage or input error.
    """
    pass


@cli.command("gate")
@click.option("--cbom", required=True, type=click.Path(exists=False), help="Path to CycloneDX 1.6 CBOM JSON.")
@click.option("--diff-base", default=None, help="Git branch or commit to diff against (e.g. origin/main).")
@click.option("--diff-file", default=None, type=click.Path(exists=False), help="Path to diff file.")
@click.option("--min-cars", default=56.0, type=float, callback=_threshold, help="Minimum acceptable CARS score, 0-100 (default: 56.0).")
@click.option("--fail-on-regression/--no-fail-on-regression", default=False, help="Fail if PR diff touches vulnerable primitives (needs --diff-file or --diff-base).")
@click.option("--fail-on-disallowed", is_flag=True, default=False, help="Alias for --fail-on-regression.")
@click.option("--allow-disallowed", is_flag=True, default=False, help="Do not fail the gate on Grade-F components.")
@click.option("--profile", default="default", help="Weight profile: default, embedded-iot, cloud-enterprise.")
@click.option("--d1-mode", default="scenario", type=click.Choice(["scenario", "empirical"]), help="d1 calculation mode.")
@click.option("--sarif-out", default=None, type=click.Path(), help="Path to write SARIF 2.1.0 output.")
@click.option("--json-out", default=None, type=click.Path(), help="Path to write JSON summary.")
def gate_cmd(
    cbom: str,
    diff_base: Optional[str],
    diff_file: Optional[str],
    min_cars: float,
    fail_on_regression: bool,
    fail_on_disallowed: bool,
    allow_disallowed: bool,
    profile: str,
    d1_mode: str,
    sarif_out: Optional[str],
    json_out: Optional[str],
):
    """Enforce CI/CD Gate policy on CBOM and git diff."""
    fail_reg = fail_on_regression or fail_on_disallowed
    diff_text = _read_diff(diff_file, diff_base) if fail_reg else ""

    exit_code, result = _run(
        cbom_path=cbom,
        min_cars=min_cars,
        diff_text=diff_text,
        fail_on_regression=fail_reg,
        profile=profile,
        d1_mode=d1_mode,
        sarif_out=sarif_out,
        json_out=json_out,
        allow_disallowed=allow_disallowed,
    )

    if exit_code == 0:
        click.echo(f"PASS: CARS score {result['cars_score']:.1f} ({result['tier']}) >= threshold {min_cars:.1f}")
    else:
        click.echo("FAIL: Gate policy violated:")
        for r in result["reasons"]:
            click.echo(f"  - {r}")

    sys.exit(exit_code)


@cli.command("evaluate")
@click.option("--cbom", required=True, type=click.Path(exists=False), help="Path to CycloneDX 1.6 CBOM JSON.")
@click.option("--min-cars", default=56.0, type=float, callback=_threshold, help="Exit 1 when the score is below this, 0-100 (default: 56.0).")
@click.option("--profile", default="default", help="Weight profile: default, embedded-iot, cloud-enterprise.")
@click.option("--d1-mode", default="scenario", type=click.Choice(["scenario", "empirical"]), help="d1 calculation mode.")
@click.option("--sarif-out", default=None, type=click.Path(), help="Path to write SARIF output.")
@click.option("--json-out", default=None, type=click.Path(), help="Path to write JSON summary.")
@click.option("--gitlab-report", default=None, type=click.Path(), help="Path to write GitLab container scanning report.")
def evaluate_cmd(
    cbom: str,
    min_cars: float,
    profile: str,
    d1_mode: str,
    sarif_out: Optional[str],
    json_out: Optional[str],
    gitlab_report: Optional[str],
):
    """Evaluate CARS agility score from a CBOM (exit 1 below --min-cars)."""
    exit_code, result = _run(
        cbom_path=cbom,
        min_cars=min_cars,
        profile=profile,
        d1_mode=d1_mode,
        sarif_out=sarif_out,
        json_out=json_out,
        gitlab_out=gitlab_report,
        allow_disallowed=True,  # evaluate reports a score; `gate` enforces Grade-F
    )

    click.echo(f"CARS Score: {result['cars_score']:.1f} (Tier: {result['tier']})")
    for k, v in sorted(result["dimensions"].items()):
        click.echo(f"  {k}: {v:.4f}")

    sys.exit(exit_code)


_PEM_PRIVATE_KEY = re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")
# heuristic list of FIPS-disallowed primitives (names only, never matched content)
_DISALLOWED = re.compile(rb"(?i:\b(?:md5|rc4|3des|des-ede3?|sha-?1)\b)|\bDES\b")


def _git(*args: str) -> bytes:
    res = subprocess.run(["git", *args], capture_output=True, check=False)
    if res.returncode != 0:
        raise OSError(res.stderr.decode(errors="replace").strip() or "git failed")
    return res.stdout


@cli.command("check-staged")
@click.option("--strict-keys/--no-strict-keys", default=True, help="Reject hardcoded private/secret keys.")
@click.option("--forbid-fips-disallowed/--allow-fips-disallowed", default=True, help="Reject FIPS-disallowed classical crypto.")
def check_staged_cmd(strict_keys: bool, forbid_fips_disallowed: bool):
    """Pre-commit hook: scan staged blobs for private keys and disallowed primitives.

    Regex heuristics over `git show :path`. Matched content is never printed.
    """
    try:
        names = _git("diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR").split(b"\0")
        staged = [n.decode("utf-8", "surrogateescape") for n in names if n]
        findings = []
        for path in staged:
            blob = _git("show", f":{path}")
            if strict_keys and (_PEM_PRIVATE_KEY.search(blob) or has_hardcoded_key(blob)):
                findings.append(f"{path}: hardcoded private key material")
            if forbid_fips_disallowed and _DISALLOWED.search(blob):
                findings.append(f"{path}: FIPS-disallowed primitive")
    except OSError as exc:
        _fail(f"git failed: {exc}")

    if not staged:
        click.echo("check-staged: No staged files to check.")
        sys.exit(0)
    if findings:
        click.echo("check-staged: FAIL")
        for f in findings:
            click.echo(f"  - {f}")
        sys.exit(EXIT_POLICY)
    click.echo(f"check-staged: Inspected {len(staged)} staged files. Clean.")
    sys.exit(0)


@cli.command("scan")
@click.argument("target_path", type=click.Path(exists=False), default=".")
@click.option("--output", "-o", default="cbom.json", help="Output path for generated CycloneDX 1.6 CBOM.")
def scan_cmd(target_path: str, output: str):
    """Fallback scanner generating a baseline CycloneDX 1.6 CBOM."""
    baseline_cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [],
    }
    with open(output, "w", encoding="utf-8") as fh:
        json.dump(baseline_cbom, fh, indent=2)
    click.echo(f"scan: Baseline CBOM written to {output}")
    sys.exit(0)


def main():
    cli()


if __name__ == "__main__":
    main()
