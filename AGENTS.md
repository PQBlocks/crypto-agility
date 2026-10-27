# AGENTS.md: pqblocks-agility

Guidance for AI coding agents integrating or invoking `pqblocks-agility`.

## Purpose & Scope

- **What it does:** Ingests CycloneDX 1.6 CBOM JSON files, computes Cryptographic Agility Readiness Scores (CARS) across 5 dimensions, and enforces CI/CD build gates on git pull request diffs.
- **What it is NOT:** It is not a cryptographic algorithm implementation. It performs no key generation, encryption, or digital signing.
- **Install:** `pip install pqblocks-agility`

---

## Canonical Imports & APIs

```python
from pqblocks_agility.cbom import parse_cbom, parse_cbom_dict
from pqblocks_agility.cars_scoring import score_cbom
from pqblocks_agility.ci_gate import evaluate_gate
from pqblocks_agility.cli import compute_cars_score

# 1. Parse CBOM
cbom = parse_cbom("path/to/cbom.json")

# 2. Compute CARS readiness score and dimension breakdown
cars_score, dimensions = compute_cars_score(cbom, profile="default")

# 3. Evaluate CI gate
gate_result = evaluate_gate(cbom, min_cars=60.0, diff=pr_diff_text, sarif_out="results.sarif")
```

CLI invocations:
```bash
# Evaluate agility score from a CBOM
pqblocks-agility evaluate cbom.json --json

# Gate pull request
pqblocks-agility gate --cbom cbom.json --diff-file pr.diff --min-cars 60.0 --sarif results.sarif
```

---

## Agent Pitfalls & Traps

1. **CBOM Version Enforcement:**
   - Input CBOMs must specify `"specVersion": "1.6"`. Any other version raises `CBOMVersionError`.
2. **Algorithm Property Resolution:**
   - Components should either carry `pqblocks-scan.grade` property or a standard algorithm identifier in `name` / `cryptoProperties.algorithmProperties.parameterSetIdentifier`. Unrecognized primitives raise `MissingGradeError`.
3. **Offline Scoring Scenario Defaults:**
   - In standalone offline evaluation without dynamic repository scanning, dimensions $d_1$ (inventory completeness), $d_4$ (toolchains), and $d_5$ (governance) default to 0.50 (scenario mode).
4. **Git Diff Format:**
   - In PR mode (`--diff-file`), input must be unified diff text (`git diff`). Do not pass patch files with binary encodings.
