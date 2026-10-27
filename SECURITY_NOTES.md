# Security notes: pqblocks-agility

## What this package is

`pqblocks-agility` is an **analytics engine and continuous-integration gate**, not a cryptographic implementation.
- It calculates readiness scores from CycloneDX 1.6 Cryptographic Bills of Materials (CBOM) and inspects git diffs.
- It performs no encryption, decryption, hashing, or key exchange.
- It generates no cryptographic keys, nonces, or tokens, and handles no sensitive credentials.
- Its outputs (CARS scores, gate decisions, SARIF reports) are automated policy aids for engineering organizations, not formal regulatory compliance certifications.

---

## Input Handling & Denial of Service

- **CBOM JSON Parsing:** CBOM files are parsed with Python's standard `json` module. Files over 50 MiB, `NaN`/`Infinity`, over-long integers, pathological nesting (`RecursionError`), wrong container types and component nesting deeper than 64 levels are all rejected as `CBOMParseError` (exit code 2), never as an uncaught traceback.
- **Grades are derived, not trusted:** a component's grade comes from the algorithm table. A CBOM-declared `pqblocks-scan.grade` may only be equal to or worse than the derived grade (otherwise `InvalidGradeError`), `quantum_vulnerable` can never mask a D/E/F grade, booleans are parsed strictly, and a claimed `nistQuantumSecurityLevel` is never a source of Grade A (it is only cross-checked against known ML-KEM/ML-DSA parameter sets). Unknown algorithms raise `MissingGradeError`. Only `cryptographic-asset` components (or ones carrying `cryptoProperties` / `pqblocks-scan.*` properties) are graded; libraries are skipped. An attacker who can edit the CBOM can still omit components or rename algorithms: the CBOM must come from a trusted scanner step.
- **Git Diff Evaluation:** The regression firewall fails closed: a missing/unreadable diff file, a failing `git diff`, a non-empty diff with no parsable file header, or a vulnerable component with no location exits 2 / fails instead of passing. `--diff-base` values starting with `-` are rejected and `git diff` is invoked with `--` and without a shell.
- **`check-staged`:** regex heuristics over staged blobs; matched content is never printed. It is a guard rail, not a secret scanner.
- **Version Enforcement:** Only CycloneDX `specVersion == "1.6"` is supported; unsupported versions raise `CBOMVersionError` and fail fast without parsing ambiguous components.

---

## Cryptographic RNG & Zeroization

- **RNG:** No cryptographic random number generation is performed.
- **Zeroization:** Not applicable. The process handles no secret keys, private keys, or plaintext data.

---

## Dependencies & Supply Chain

- Runtime dependencies: `click` (CLI framework).
- Pure Python: No C extensions, external binary dependencies, or network connections during execution.
