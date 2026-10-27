"""CI/CD Gate integration (feature 4).

Implements the CI gate logic per spec section 5 (5.4 dual-trigger policy),
satisfying the pre-existing test file tests/test_gate_policy.py:
  E14  PR diff with no crypto changes -> gate passes
  E15  PR diff introduces Grade-F    -> gate fails (regression firewall)
  Absolute score failure / pass
  SARIF + JSON summary output

Derivation is ideas-only from the spec's openly published rules. The
regression firewall is a heuristic: a vulnerable CBOM component whose file
location is touched by added diff lines is treated as a new introduction of
a Grade-F / Disallowed primitive (spec 5.4 condition 2).
"""

from __future__ import annotations

import json
import posixpath
import shlex
from typing import Any, Dict, List, Optional

from pqblocks_agility.cbom import CBOM
from pqblocks_agility.cars_scoring import compute_cars_score


# ---------------------------------------------------------------------------
# CARS tier boundaries per spec section 1.4
# ---------------------------------------------------------------------------
CARS_TIERS = [
    (0.0, 30.0, "Critical"),
    (30.0, 55.0, "At-Risk"),
    (55.0, 75.0, "Transitional"),
    (75.0, 90.0, "Advanced"),
    (90.0, 100.0, "Ready"),
]


def get_cars_tier(cars_score: float) -> str:
    """Map CARS score to tier per spec section 1.4.

    Boundaries: <=30->Critical, <=55->At-Risk, <=75->Transitional,
    <=90->Advanced, >90->Ready.
    Out-of-range values clamp to the nearest tier.
    """
    if cars_score <= 30.0:
        return "Critical"
    if cars_score <= 55.0:
        return "At-Risk"
    if cars_score <= 75.0:
        return "Transitional"
    if cars_score <= 90.0:
        return "Advanced"
    return "Ready"


def _added_lines(diff_text: str) -> List[str]:
    """Return the content of diff lines that add a new line (single '+').

    '++' file headers and pure '+++' are excluded; the leading '+' is kept in
    the returned strings so callers can match against raw diff text.
    """
    out: List[str] = []
    for line in diff_text.splitlines():
        if line.startswith("+") and not line.startswith("++"):
            out.append(line)
    return out


class DiffError(ValueError):
    """The diff cannot be trusted (non-empty but unparsable); the firewall must not pass."""


def _strip_ab(path: str) -> str:
    return path[2:] if path[:2] in ("a/", "b/") else path


def _diff_files(diff_text: str) -> set:
    """Changed paths from 'diff --git' headers (prefixed, no-prefix, quoted, spaced) and '+++' lines."""
    files = set()
    for line in diff_text.splitlines():
        paths: List[str] = []
        if line.startswith("diff --git "):
            rest = line[len("diff --git "):]
            try:
                paths = shlex.split(rest)
            except ValueError:
                paths = []
            if len(paths) != 2:  # unquoted path with spaces: both sides are the same length
                mid = len(rest) // 2
                paths = [rest[:mid], rest[mid + 1:]] if len(rest) % 2 and rest[mid] == " " else []
        elif line.startswith("+++ "):
            p = line[4:].split("\t")[0].strip().strip('"')
            paths = [] if p == "/dev/null" else [p]
        for p in paths:
            files.update({p, _strip_ab(p)})
    return files


def _diff_introduces_new_crypto(diff_text: str, cbom: CBOM) -> List[str]:
    """Spec 5.4 condition 2: report vulnerable components whose file the diff touches.

    Fails closed: a non-empty diff with no parsable file header raises DiffError, and a
    vulnerable component with no location is reported (it cannot be cleared).
    """
    if not diff_text or not diff_text.strip():
        return []

    diff_files = _diff_files(diff_text)
    if not diff_files:
        raise DiffError("diff is non-empty but no file headers could be parsed")

    reasons: List[str] = []
    for comp in cbom.components:
        if not comp.quantum_vulnerable:
            continue
        if not comp.location:
            reasons.append(
                f"vulnerable primitive {comp.algorithm!r} ({comp.component_id}) has no location; "
                "cannot verify it is outside the diff"
            )
            continue
        file_part = posixpath.normpath(comp.location.split(":")[0])
        if any(file_part == f or file_part.endswith("/" + f) for f in map(posixpath.normpath, diff_files)):
            reasons.append(
                f"PR diff introduces Grade-{comp.grade} vulnerable "
                f"primitive {comp.algorithm!r} in {file_part}"
            )
    return reasons


def evaluate_gate(
    cbom: CBOM,
    min_cars: float = 56.0,
    diff: str = "",
    fail_on_regression: bool = False,
    sarif_out: Optional[str] = None,
    json_out: Optional[str] = None,
    profile: str = "default",
    d1_mode: str = "scenario",
    allow_disallowed: bool = False,
) -> Dict[str, Any]:
    """Evaluate the crypto-agility gate (the one implementation behind API and CLI).

    Fails when CARS < min_cars, when any Grade-F component exists (unless
    allow_disallowed), or, with fail_on_regression, when the diff touches a
    vulnerable component. Raises DiffError on an unparsable non-empty diff.

    Returns:
        Dict with keys: exit_code, passed, regression_detected,
        regression_reasons, reasons, cars_score, tier, dimensions.
    """
    cars_score, dimensions = compute_cars_score(cbom, profile=profile, d1_mode=d1_mode)
    tier = get_cars_tier(cars_score)

    result: Dict[str, Any] = {
        "exit_code": 0,
        "passed": True,
        "regression_detected": False,
        "regression_reasons": [],
        "reasons": [],
        "cars_score": cars_score,
        "tier": tier,
        "dimensions": dimensions,
    }

    # 1. Absolute score threshold check (spec 5.4 condition 1)
    if cars_score < min_cars:
        result["passed"] = False
        result["exit_code"] = 1
        result["reasons"].append(
            f"CARS score {cars_score} below threshold {min_cars} (tier {tier})"
        )

    # 1b. Any Grade-F component fails, however good the mean is
    if not allow_disallowed:
        for comp in cbom.components:
            if comp.grade == "F":
                result["passed"] = False
                result["exit_code"] = 1
                result["reasons"].append(
                    f"Grade F primitive {comp.algorithm!r} ({comp.component_id}) "
                    f"at {comp.location or 'unknown'}"
                )

    # 2. Regression firewall check (diff mode, spec 5.4 condition 2)
    if fail_on_regression and diff:
        regression_reasons = _diff_introduces_new_crypto(diff, cbom)
        if regression_reasons:
            result["regression_detected"] = True
            result["regression_reasons"] = regression_reasons
            result["passed"] = False
            result["exit_code"] = 1
            result["reasons"].extend(regression_reasons)

    # 3. SARIF output
    if sarif_out:
        _write_sarif(sarif_out, result, dimensions, cbom)

    # 4. JSON summary output
    if json_out:
        _write_json(json_out, result)

    return result


# ---------------------------------------------------------------------------
# SARIF 2.1.0 output (spec section 6)
# ---------------------------------------------------------------------------

def _write_sarif(
    path: str,
    result: Dict[str, Any],
    dimensions: Dict[str, float],
    cbom: CBOM,
) -> None:
    """Write a SARIF 2.1.0 document to *path*."""
    sarif: Dict[str, Any] = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pqblocks-agility",
                        "version": "0.1.0",
                        "rules": [
                            {"id": "CARS-D1", "shortDescription": {"text": "Inventory Completeness"}},
                            {"id": "CARS-D2", "shortDescription": {"text": "Algorithm Compliance"}},
                            {"id": "CARS-D3", "shortDescription": {"text": "Architectural Decoupling"}},
                            {"id": "CARS-D4", "shortDescription": {"text": "Toolchain Readiness"}},
                            {"id": "CARS-D5", "shortDescription": {"text": "Governance & Compliance"}},
                        ],
                    }
                },
                "properties": {
                    "CARS-D1": dimensions.get("d1", 0.0),
                    "CARS-D2": dimensions.get("d2", 0.0),
                    "CARS-D3": dimensions.get("d3", 0.0),
                    "CARS-D4": dimensions.get("d4", 0.0),
                    "CARS-D5": dimensions.get("d5", 0.0),
                    "CARSComposite": result["cars_score"],
                    "CARS_Tier": result["tier"],
                    "scoring_mode": "scenario",
                },
                "results": [],
            }
        ],
    }

    # One informational result per vulnerable (Grade-F / quantum_vulnerable)
    # component, mapped to rule CARS-D2 with a physical location where known.
    for comp in cbom.components:
        if comp.grade == "F" or comp.quantum_vulnerable:
            location_block: Dict[str, Any] = {}
            if comp.location:
                file_part = comp.location.split(":")[0]
                region: Dict[str, Any] = {}
                if ":" in comp.location:
                    try:
                        region["startLine"] = int(comp.location.split(":")[1])
                    except ValueError:
                        pass
                location_block = {
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_part},
                        **({"region": region} if region else {}),
                    }
                }
            entry: Dict[str, Any] = {
                "ruleId": "CARS-D2",
                "level": "warning",
                "message": {
                    "text": f"Grade {comp.grade} finding: {comp.algorithm} "
                            f"at {comp.location or 'unknown'}"
                },
            }
            if location_block:
                entry["locations"] = [location_block]
            sarif["runs"][0]["results"].append(entry)

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2)


def _write_json(path: str, result: Dict[str, Any]) -> None:
    """Write a JSON summary document to *path*."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
