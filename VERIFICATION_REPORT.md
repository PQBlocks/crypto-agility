# Verification report: pqblocks-agility 0.1.0

This is an internal self-verification report detailing test execution, packaging checks, and scoring validations for `pqblocks-agility` 0.1.0. This is not an external audit or third-party validation.

## Summary

| Area | Result |
|---|---|
| Correctness | 186 automated tests pass on Python 3.14; on the installed wheel under Python 3.11-3.14 the run is 185 passed, 1 skipped (the README doc test needs the repository checkout) |
| Coverage | 96% statement coverage (590 statements, 24 missed) |
| Installation | Clean wheel installation with dependencies (`click`) on Python 3.11, 3.12, 3.13, 3.14 |
| Examples | All 2 standalone example scripts pass cleanly across Python 3.11, 3.12, 3.13, 3.14 |
| Packaging | Source distribution and wheel build cleanly; `twine check --strict` passes |
| Telemetry formats | OASIS SARIF 2.1.0 and CycloneDX 1.6 CBOM |
| Mathematical model | 5 / 5 reference CARS equation vectors replicated within tolerance ([BENCHMARKS.md](BENCHMARKS.md)) |
| Security review | 3 critical + 5 high findings fixed (see Defects Found); remaining items listed there; the tool performs no cryptographic operations |

---

## Review Checks Completed

| Check | Purpose | Result |
|---|---|---|
| Check 1 (design review) | Scope, sources (Costa 2026), and CARS dimensions identified | Pass |
| Check 2 (spec review) | 5-dimension scoring formula, weight profiles, and SARIF rules defined | Pass |
| Check 3 (correctness) | Full suite of 186 tests; 96% statement coverage | Pass |
| Check 4 (benchmark review) | Offline golden equation replication across 5 reference vectors | Pass |
| Check 5 (adversarial review) | Malformed CBOMs, missing grades, invalid specVersion, empty assets | Pass |
| Release check | Wheel build, clean venv installation, 4 Python versions, 0 leak hits | Pass |

---

## Verification Test Evidence

```
build sdist+wheel                  PASS  Successfully built dist/pqblocks_agility-0.1.0-py3-none-any.whl
twine check --strict               PASS  Checking dist/*: PASSED
python 3.11-3.14: tests            PASS  185 passed, 1 skipped (installed wheel, after review fixes)
examples (evaluate_cbom, ci_regression_gate) PASS on 3.11-3.14
leak gate (folder + wheel + sdist) PASS  0 leak hits
```

---

## Defects Found and Review Disclosures

Crypto-integration review (2026-10-26) found a fail-open gate. Fixed, each with a negative test in `tests/test_review_fixes.py`:
- C1: `check-staged` was a stub that printed "Clean"; it now scans staged blobs and exits 1 on private keys or disallowed primitives.
- C2: the regression firewall failed open (missing diff, failing `git diff`, no-prefix/quoted/`./`/absolute paths, unlocated components); it now exits 2 or fails.
- C3: CBOM-declared grades and `quantum_vulnerable` could override the algorithm table; grades are now derived and a declaration can only be worse.
- H1: the `nistQuantumSecurityLevel` fallback graded unknown and classical algorithms A; removed, symmetric/hash/EdDSA families added explicitly, level claims cross-checked.
- H2: nested components were never graded; now walked (depth cap 64).
- H3: one Grade-F component among many A components passed; any Grade-F now fails by default (`--allow-disallowed` opts out).
- H4: wrong JSON shapes, huge/deep/non-finite input and non-crypto components crashed or padded the score; now clean exit 2 and skipped.
- H5: the API and CLI used different d3 values; one `compute_cars_score` now serves both.
- M1, M2, M3, M5: threshold validation, `--diff-base` option injection, distinct exit codes (0/1/2), README CLI examples.

Still open: M4 (tier wording), M6 (`scan` is a template generator), M7 (partly: hybrid names now grade B, `HashML-DSA-*` still grades F), M8 (`click` pin), L1 (SARIF level and gate-decision result), no fuzz target, `ast_decoupling` source-code inspection is still never invoked by the gate.

During preparation of this release, internal naming identifiers and property namespaces were updated:
- The driver tool name in exported SARIF logs was changed from the internal project name to `pqblocks-agility`.
- CBOM parser property prefixes were updated to `pqblocks-scan.*` while maintaining backwards-compatibility for legacy CBOM documents.
- The 5-dimension model offline scenario defaults ($d_1 = d_4 = d_5 = 0.50$) are explicitly disclosed in documentation.
