# Testing: pqblocks-agility

This document details the test architecture, execution procedures, and statement coverage metrics for `pqblocks-agility`.

## Test Environment

- **Runner:** `pytest` 9.1.1 with `pytest-cov` 7.1.0
- **Supported Python runtimes:** 3.11, 3.12, 3.13, 3.14
- **Dependencies under test:** `click`

---

## Running the Test Suite

```bash
cd packages/pqblocks-agility
PYTHONPATH=src pytest -q
```

### With statement coverage

```bash
cd packages/pqblocks-agility
PYTHONPATH=src pytest --cov=pqblocks_agility
```

---

## Test Suite Architecture

The test suite consists of **186 automated tests** across 10 test modules:

| Module | Test Count | Scope |
|---|---|---|
| `tests/test_ast_decoupling.py` | 5 | AST decoupling heuristic verification, call-site analysis |
| `tests/test_cars_scoring.py` | 6 | CARS mathematical formula, weight vector invariants ($w_1..w_5$) |
| `tests/test_cbom.py` | 33 | CycloneDX 1.6 parsing, grade derivation ($A..F$), edge cases (empty CBOM, version mismatch) |
| `tests/test_ci_gate.py` | 5 | Threshold policy gates, pull request regression detection |
| `tests/test_review_fixes.py` | 57 | Negative tests for the crypto review findings C1-C3, H1-H5, M1-M3, M5 (reproducers R1-R14) |
| `tests/test_cli.py` | 18 | Click CLI commands (`evaluate`, `gate`, `check-staged`, `scan`), options, exit codes |
| `tests/test_decouple.py` | 20 | Static decoupling patterns, abstraction providers, configuration heuristics |
| `tests/test_gate_policy.py` | 7 | Gate evaluation logic, threshold boundaries, regression warnings |
| `tests/test_sarif_export.py` | 20 | SARIF 2.1.0 export formatting, rule IDs (`CARS-D1`..`CARS-D5`), level mappings |
| `tests/test_suite.py` | 15 | End-to-end integration suite, offline benchmark card harness contract |
| **Total** | **186** | **All passing** |

---

## Statement Coverage Breakdown

Measured on Python 3.14.8 with `pytest-cov`:

| Module | Statements | Missed | Coverage |
|---|---|---|---|
| `src/pqblocks_agility/__init__.py` | 1 | 0 | 100% |
| `src/pqblocks_agility/ast_decoupling.py` | 33 | 4 | 88% |
| `src/pqblocks_agility/cars_scoring.py` | 30 | 2 | 93% |
| `src/pqblocks_agility/cbom.py` | 173 | 6 | 97% |
| `src/pqblocks_agility/ci_gate.py` | 113 | 2 | 98% |
| `src/pqblocks_agility/cli.py` | 147 | 8 | 95% |
| `src/pqblocks_agility/decouple.py` | 50 | 2 | 96% |
| `src/pqblocks_agility/sarif.py` | 2 | 0 | 100% |
| `src/pqblocks_agility/sarif_export.py` | 41 | 0 | 100% |
| **Total** | **590** | **24** | **96%** |

---

## Standalone Examples Verification

Two example scripts in `examples/` demonstrate standard workflows:

```bash
# 1. Evaluate agility score from a sample CBOM
PYTHONPATH=src python3 examples/evaluate_cbom.py

# 2. CI/CD regression firewall with SARIF 2.1.0 telemetry export
PYTHONPATH=src python3 examples/ci_regression_gate.py
```
