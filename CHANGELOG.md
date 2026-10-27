# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security
- Fixed a fail-open CI gate found in crypto review. `check-staged` now inspects staged blobs; the regression firewall exits 2 on a missing/unparsable diff and handles no-prefix, quoted, `./` and absolute paths; grades are derived from the algorithm table (declared grades may only be worse; `quantum_vulnerable` cannot mask D/E/F); the `nistQuantumSecurityLevel` fallback is removed; nested components are graded; any Grade-F component fails the default gate (`--allow-disallowed` to opt out); malformed or oversized input exits 2; non-crypto components are skipped.

### Changed
- Exit codes: 0 pass, 1 policy failure, 2 usage/input error (a missing CBOM was 1). `evaluate` now honours `--min-cars`. `--min-cars` must be within 0-100 (NaN rejected). `--diff-base` values starting with `-` are rejected.
- One scoring implementation (`cars_scoring.compute_cars_score`) for the CLI and `evaluate_gate`; `score_cbom` now includes the real d3 instead of the 0.50 placeholder. Removed duplicate `decouple.compute_d3`.

## [0.1.0] - 2026-10-25

### Added
- CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) JSON parser and validator.
- Implementation of the 5-dimension CARS readiness scoring engine (Costa 2026).
- Configurable weight profiles: `default`, `cloud-enterprise`, and `embedded-iot`.
- AST decoupling heuristics analyzer computing architectural decoupling ratios ($d_3$).
- CI/CD regression firewall evaluating git diffs and blocking re-introduction of deprecated cryptography.
- OASIS SARIF 2.1.0 telemetry log exporter for GitHub Advanced Security and GitLab CI.
- Pre-commit hook command (`check-staged`) scanning staged changes.
- Click-based command-line interface `pqblocks-agility` supporting `evaluate`, `gate`, `check-staged`, and `scan`.
- 129 automated tests verifying CBOM parsing, CARS calculations, decoupling heuristics, and CLI gate behavior.
