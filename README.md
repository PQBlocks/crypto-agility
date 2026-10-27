# pqblocks-agility

Computes Cryptographic Agility Readiness Scores (CARS) and acts as a CI/CD regression firewall for CycloneDX 1.6 Cryptographic Bills of Materials (CBOM).
Use it to quantitatively measure how easily your codebase can transition away from deprecated classical cryptography to post-quantum standards, and fail pull requests that re-introduce quantum-vulnerable primitives.
Implements the 5-dimension CARS model (Costa, IACR ePrint 2026/1467) and OASIS SARIF 2.1.0 telemetry export.

```bash
pip install pqblocks-agility
```

```python
import json
from pqblocks_agility.cbom import parse_cbom_dict
from pqblocks_agility.cli import compute_cars_score

cbom_data = {
    "bomFormat": "CycloneDX", "specVersion": "1.6",
    "serialNumber": "urn:uuid:6c361972-23c3-4d4b-9721-a47fa266184a", "version": 1,
    "components": [{"type": "cryptographic-asset", "name": "ML-KEM-768",
                    "properties": [{"name": "pqblocks-scan.algorithm", "value": "ML-KEM-768"},
                                   {"name": "pqblocks-scan.grade", "value": "A"}]}]
}
score, dims = compute_cars_score(parse_cbom_dict(cbom_data))
print(f"CARS score: {score:.1f} / 100.0 (Grade A)")
```

From the command line:

```bash
# Evaluate agility score from a CBOM (exit 1 below --min-cars)
pqblocks-agility evaluate --cbom cbom.json --json-out summary.json

# Gate a GitHub Pull Request against regression
pqblocks-agility gate --cbom cbom.json --diff-file pr.diff --fail-on-regression --min-cars 60.0 --sarif-out results.sarif
```

Exit codes: `0` pass, `1` policy failure (score below threshold, a Grade-F component, or a regression), `2` usage or input error (missing or malformed CBOM, missing or unparsable diff, bad option value).

---

## Why PQBlocks

- **Standardized scoring:** Implements the formal 5-dimension weighted composite model ($w = [0.20, 0.25, 0.25, 0.15, 0.15]$) covering inventory completeness, algorithm compliance, decoupling, toolchains, and governance.
- **CI/CD regression firewall:** Prevents pull requests from slipping deprecated classical algorithms (MD5, SHA-1, 1024-bit RSA) into repositories with established migration thresholds.
- **GitHub Advanced Security integration:** Emits standard SARIF 2.1.0 logs uploaded directly to GitHub Code Scanning or GitLab Security dashboards.
- **Pure Python:** No native C libraries or GPU requirements. Runs in milliseconds on standard CI runners.

---

## Usage

### Command Line Interface

```bash
pqblocks-agility [OPTIONS] COMMAND [ARGS]...
```

Commands:
- `evaluate [OPTIONS]`: Evaluates CARS score and dimension breakdowns from a CycloneDX 1.6 CBOM.
  - `--cbom PATH`: Path to CycloneDX 1.6 CBOM JSON.
  - `--profile [default|cloud-enterprise|embedded-iot]`: Weight distribution profile.
  - `--d1-mode [scenario|empirical]`: Inventory completeness estimation mode.
  - `--min-cars FLOAT`: Exit 1 when the score is below this (0-100, default: 56.0).
  - `--json-out PATH`, `--sarif-out PATH`, `--gitlab-report PATH`: Report outputs.
- `gate [OPTIONS]`: Enforces CI/CD gate policies on CBOM and git diffs.
  - `--cbom PATH`: Path to CycloneDX 1.6 CBOM JSON.
  - `--diff-file PATH` / `--diff-base REF`: Diff source for the regression firewall.
  - `--fail-on-regression`: Enable the regression firewall (off by default). Requires `--diff-file` or `--diff-base`; a missing or unparsable diff exits 2, never passes.
  - `--allow-disallowed`: Do not fail on Grade-F components. By default any Grade-F component fails the gate.
  - `--min-cars FLOAT`: Minimum CARS score threshold, 0-100 (default: 56.0).
  - `--sarif-out PATH`, `--json-out PATH`: Report outputs.
- `check-staged [OPTIONS]`: Pre-commit hook scanning staged blobs (`git show :path`) for private-key material and FIPS-disallowed primitive names (regex heuristics; exits 1 on a hit and never prints matched content).
- `scan [OPTIONS] SOURCE_DIR`: Writes an empty baseline CBOM template. It does not inspect SOURCE_DIR; an empty inventory is not evidence that no crypto exists.

---

## CARS 5-Dimension Agility Model

The readiness score is calculated as a weighted composite:
$$\text{CARS} = 100 \sum_{i=1}^5 w_i d_i$$

| Dimension | Meaning | Metric Basis |
|---|---|---|
| $d_1$ ($w_1 = 0.20$) | Inventory Completeness | Ratio of discovered components vs repository complexity |
| $d_2$ ($w_2 = 0.25$) | Algorithm Compliance | Mean algorithm grade ($A=1.0, B=0.85, C=0.60, D=0.30, E/F=0.0$) |
| $d_3$ ($w_2 = 0.25$) | Architectural Decoupling | Ratio of abstracted vs hardcoded direct cryptographic call sites |
| $d_4$ ($w_4 = 0.15$) | Toolchain Readiness | CI/CD automation and automated scanning integration |
| $d_5$ ($w_5 = 0.15$) | Governance Alignment | Sunset planning, cryptographic migration policies |

Score tiers:
Tiers as implemented in `ci_gate.get_cars_tier`: Critical $\le 30$, At-Risk $\le 55$, Transitional $\le 75$, Advanced $\le 90$, Ready $> 90$.

---

## API Reference

| Module | Function / Class | Purpose |
|---|---|---|
| `pqblocks_agility.cbom` | `parse_cbom(path: str) -> CBOM` | Parse a CycloneDX 1.6 CBOM file into a structured dataclass |
| | `parse_cbom_dict(data: dict) -> CBOM` | Parse a CBOM dictionary in-memory |
| | `CBOM`, `CBOMComponent` | Dataclasses holding components, algorithm properties, and grades |
| `pqblocks_agility.cars_scoring` | `compute_cars_score(cbom, profile, d1_mode) -> (float, dict)` | The single CARS implementation (CLI and API); `score_cbom(cbom)` is the default-profile alias |
| `pqblocks_agility.ci_gate` | `evaluate_gate(cbom, min_cars, diff, ..., allow_disallowed=False)` | Evaluate gate policy (score, Grade-F, regression firewall); raises `DiffError` on an unparsable diff |
| `pqblocks_agility.sarif_export` | `export_sarif(cbom, score, dimensions, ...)` | Generate SARIF 2.1.0 telemetry dictionary |
| `pqblocks_agility.ast_decoupling` | `compute_d3(cbom: CBOM) -> float` | Evaluate AST decoupling ratios from call site metadata |

---

## Limitations

- **CycloneDX 1.6 required:** CycloneDX 1.4/1.5/1.7 files are rejected (`CBOMVersionError`).
- **Static analysis heuristic:** $d_3$ evaluates AST call sites and configuration locations. It does not trace dynamic object loading or C shared-object symbol resolution.
- **Dimensions $d_1, d_4, d_5$ defaults:** In standalone offline CBOM evaluation, $d_1, d_4, d_5$ default to 0.50 scenario mode unless explicit CI flags or empirical scans are supplied.
- **Not a cryptographic engine:** Does not perform encryption, decryption, or signing.

---

## Security Notes

See [SECURITY_NOTES.md](SECURITY_NOTES.md) for details on AST parsing limits, denial of service mitigation, and dependency integrity.

## Verification

[TESTING.md](TESTING.md) · [BENCHMARKS.md](BENCHMARKS.md) · [EVIDENCE.md](EVIDENCE.md) · [VERIFICATION_REPORT.md](VERIFICATION_REPORT.md) · [USE_CASES.md](USE_CASES.md)

## Part of PQBlocks

[PQBlocks](https://github.com/PQBlocks) builds modular, verified building blocks for post-quantum cryptographic transitions.
