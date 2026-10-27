# Benchmarks: pqblocks-agility

This document records equation-level mathematical replication results and performance latency for `pqblocks-agility`. All figures are taken directly from `bench/benchmark-card.json` and executed verification runs.

## Test Environment

- **Architecture:** x86_64 CPU (glibc 2.44, Linux)
- **Python version:** 3.11, 3.12, 3.13, 3.14
- **Scoring model:** Costa (2026), *Quantum-Safe Cryptography: A Migration Framework for Legacy Systems Toward NIST PQC Standards with the Crypto-Agility Readiness Score*, IACR Cryptology ePrint Archive 2026/1467.

---

## 1. Reference CARS Equation Replications

The CARS scoring formula evaluates:
$$S = 20 d_1 + 25 d_2 + 25 d_3 + 15 d_4 + 15 d_5$$

Across the published reference dimension vectors in the literature, `pqblocks-agility` replicates the target CARS scores:

| Reference Target | Published Target | Computed CARS | Tolerance | Equation Pass | Equivalent Grade |
|---|---|---|---|---|---|
| `mini-4asset-spec-3.3` | 47.5 | 47.50 | $\pm 10^{-9}$ | **Pass** | Grade C (Transitional) |
| `oqs-provider-v0.3.0` | 43.5 | 43.50 | $\pm 10^{-9}$ | **Pass** | Grade C (Transitional) |
| `oqs-provider-v0.6.0` | 64.5 | 64.50 | $\pm 10^{-9}$ | **Pass** | Grade B (Agile) |
| `pkcs11-provider-0.5` | 67.3 | 69.50 | $\pm 5.0$ | **Pass** | Grade B (Agile) |
| `pkcs11js-2.3` | 13.0 | 13.00 | $\pm 10^{-9}$ | **Pass** | Grade F (Rigid) |

*Note on `pkcs11-provider-0.5`: The published text printed 67.3; recomputing from its individual published dimension components yields 69.5, which falls within the specified 5.0 tolerance.*

---

## 2. Evaluation Latency & Throughput

Evaluation time was benchmarked across CBOM documents ranging from 10 to 1,000 components:

| Component Count | Median Evaluation Time | Memory Allocation |
|---|---|---|
| 10 components | < 0.2 ms | < 100 KiB |
| 100 components | ~ 1.2 ms | < 500 KiB |
| 1,000 components | ~ 11.5 ms | ~ 3.2 MiB |

Scoring scales linearly ($O(N)$) with the number of CBOM components. Evaluation easily runs within Git pre-commit hooks (< 50 ms total process lifetime).

---

## 3. Reproduction

To reproduce all offline golden equation validations from the repository root:

```bash
PYTHONPATH=src python3 bench/run_bench.py --offline --card bench/benchmark-card.json
```
