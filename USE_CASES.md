# Use cases: pqblocks-agility

Each runnable example below is located in `examples/` and verifies its own execution output.

---

## 1. Evaluating Cryptographic Agility Readiness (CARS)

You have generated a CycloneDX 1.6 CBOM (e.g. via `pqblocks-scan`) and want to compute the quantitative CARS readiness score:

```bash
python examples/evaluate_cbom.py
```

Output:
```
CARS score: 50.0 / 100.0
Dimensions: {'d1': 0.5, 'd2': 0.5, 'd3': 0.5, 'd4': 0.5, 'd5': 0.5}
check passed: True
```

In the shell:
```bash
pqblocks-agility evaluate cbom.json --json
```

---

## 2. GitHub Actions CI/CD Regression Firewall

You want to prevent pull requests from re-introducing deprecated classical cryptography (e.g. RSA, SHA-1, MD5) into repositories with established PQC standards:

```bash
python examples/ci_regression_gate.py
```

Output:
```
Gate passed: True
CARS score: 57.5 (Tier: Transitional)
SARIF file written: True
check passed: True
```

In GitHub Actions workflow:
```yaml
- name: Check Crypto-Agility Gate
  run: |
    git diff origin/main...HEAD > pr.diff
    pqblocks-agility gate --cbom cbom.json --diff-file pr.diff --min-cars 60.0 --sarif results.sarif

- name: Upload SARIF Results
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## 3. Git Pre-Commit Hook

Ensure local developer commits do not add unabstracted, hardcoded cryptographic keys or disallowed primitives:

```bash
# Add to .git/hooks/pre-commit
pqblocks-agility check-staged
```
Exit code 0 indicates staged changes pass policy; exit code 1 blocks commit creation.
