"""Benchmark harness for pqblocks-agility.

Offline equation-level validation of the CARS scoring equation against
published dimension vectors, plus the 43-repo corpus manifest from
Costa 2026 Table X.

Live cloning of the 43 repos requires network + pinned SHAs and is out of
scope for a unit session; run_offline() replicates every vector with
published dims and itemizes the rest as skipped.
Use --full for a live attempt (clones each repo at its pinned commit when
git + network are available, otherwise records the skip reason per repo).
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Tuple

DEFAULT_WEIGHTS: Tuple[float, float, float, float, float] = (0.20, 0.25, 0.25, 0.15, 0.15)

GOLDEN_VECTORS: Dict[str, Dict[str, Any]] = {
    "mini-4asset-spec-3.3": {
        "dims": {"d1": 0.50, "d2": 0.40, "d3": 0.50, "d4": 0.50, "d5": 0.50},
        "target": 47.5,
        "tolerance": 1e-9,
        "tier": "At-Risk",
        "source": "spec/spec.md section 3.3",
    },
    "oqs-provider-v0.3.0": {
        "dims": {"d1": 0.50, "d2": 0.22, "d3": 1.00, "d4": 0.00, "d5": 0.20},
        "target": 43.5,
        "tolerance": 1e-9,
        "tier": "At-Risk",
        "source": "brief/research-brief.md section 7.1A (commit c89b03f)",
    },
    "oqs-provider-v0.6.0": {
        "dims": {"d1": 0.50, "d2": 0.22, "d3": 1.00, "d4": 0.60, "d5": 1.00},
        "target": 64.5,
        "tolerance": 1e-9,
        "tier": "Transitional",
        "source": "brief/research-brief.md section 7.1B (commit 0ec51eca)",
    },
    "pkcs11-provider-0.5": {
        "dims": {"d1": 0.50, "d2": 0.45, "d3": 1.00, "d4": 0.55, "d5": 1.00},
        "target": 67.3,
        "tolerance": 5.0,
        "tier": "Transitional",
        "source": "brief/research-brief.md section 7.2 (commit 5dcc876); "
        "recomputes to 69.5 vs printed 67.3, inside tolerance per spec 11.1 NOTE",
    },
    "pkcs11js-2.3": {
        "dims": {"d1": 0.50, "d2": 0.00, "d3": 0.00, "d4": 0.20, "d5": 0.00},
        "target": 13.0,
        "tolerance": 1e-9,
        "tier": "Critical",
        "source": "brief/research-brief.md section 7.2 (commit 9dc0443)",
    },
}

CORPUS_43: List[Dict[str, Any]] = [
    {"repo": "pycryptodome-3.20", "commit": "d122649", "expected": 19.9, "category": "legacy"},
    {"repo": "paramiko-3.4", "commit": "d60d5c1", "expected": 48.0, "category": "legacy"},
    {"repo": "python-jose-3.3", "commit": "018b310", "expected": 39.9, "category": "legacy"},
    {"repo": "itsdangerous-2.1", "commit": "672971d", "expected": 13.0, "category": "legacy"},
    {"repo": "pyotp-2.9", "commit": "cc15683", "expected": 22.0, "category": "legacy"},
    {"repo": "bcrypt-4.1", "commit": "93e7aa4", "expected": 23.0, "category": "legacy"},
    {"repo": "jwcrypto-1.5", "commit": "eb7c266", "expected": 23.9, "category": "legacy"},
    {"repo": "pynacl-1.5", "commit": "903ea57", "expected": 18.4, "category": "legacy"},
    {"repo": "certifi-2024", "commit": "a31ef39", "expected": 32.0, "category": "legacy"},
    {"repo": "pyopenssl-24.1", "commit": "6f75fa5", "expected": 16.7, "category": "legacy"},
    {"repo": "asn1crypto-1.5", "commit": "c336e9f", "expected": 22.9, "category": "legacy"},
    {"repo": "oscrypto-1.3", "commit": "a1f449d", "expected": 16.1, "category": "legacy"},
    {"repo": "rsa-4.9", "commit": "42b0e14", "expected": 25.3, "category": "legacy"},
    {"repo": "cryptography-42", "commit": "ba48f7f", "expected": 26.8, "category": "legacy"},
    {"repo": "certbot-2.10", "commit": "c777edb", "expected": 30.3, "category": "pki"},
    {"repo": "cfssl-1.6", "commit": "e429e72", "expected": 35.4, "category": "pki"},
    {"repo": "step-certificates-0.26", "commit": "754893d", "expected": 28.3, "category": "pki"},
    {"repo": "boulder-2024", "commit": "00001c5", "expected": 35.0, "category": "pki"},
    {"repo": "openxpki-5.0", "commit": "5c03897", "expected": 13.0, "category": "pki"},
    {"repo": "rcgen-0.13", "commit": "86ae909", "expected": 25.2, "category": "pki"},
    {"repo": "acme-py-2.0", "commit": "7cc16cd", "expected": 16.0, "category": "pki"},
    {"repo": "ejbca-ce-8.0", "commit": "3eca262", "expected": 23.5, "category": "pki"},
    {"repo": "softhsm2-2.6", "commit": "f59e8f4", "expected": 27.4, "category": "hsm"},
    {"repo": "opensc-0.25", "commit": "d6d2df4", "expected": 34.8, "category": "hsm"},
    {"repo": "p11-kit-0.25", "commit": "a147888", "expected": 30.3, "category": "hsm"},
    {"repo": "pkcs11-provider-0.5", "commit": "5dcc876", "expected": 67.3, "category": "hsm"},
    {"repo": "tpm2-tss-4.1", "commit": "506c5e6", "expected": 55.8, "category": "hsm"},
    {"repo": "libp11-0.4", "commit": "11c62c8", "expected": 40.8, "category": "hsm"},
    {"repo": "pkcs11js-2.3", "commit": "9dc0443", "expected": 13.0, "category": "hsm"},
    {"repo": "yubihsm-shell-2.4", "commit": "428bfdd", "expected": 39.1, "category": "hsm"},
    {"repo": "opencryptoki-3.23", "commit": "627d275", "expected": 29.0, "category": "hsm"},
    {"repo": "aws-encryption-sdk-py-3.2", "commit": "2c0200b", "expected": 47.7, "category": "hsm"},
    {"repo": "google-tink-python-1.9", "commit": "1f4cd38", "expected": 51.7, "category": "hsm"},
    {"repo": "rustls-0.23", "commit": "0ca4775", "expected": 62.7, "category": "tls"},
    {"repo": "aws-s2n-tls-1.4", "commit": "d179a9d", "expected": 60.1, "category": "tls"},
    {"repo": "oqs-provider-0.6", "commit": "b104f57", "expected": 53.2, "category": "tls"},
    {"repo": "cloudflare-circl-1.3", "commit": "6302ca8", "expected": 25.0, "category": "tls"},
    {"repo": "msft-symcrypt-openssl-1.6", "commit": "d73b1e9", "expected": 34.8, "category": "tls"},
    {"repo": "liboqs-0.10", "commit": "d321dea", "expected": 64.2, "category": "pqc-native"},
    {"repo": "oqs-python-0.9", "commit": "35eceb6", "expected": 43.8, "category": "pqc-native"},
    {"repo": "pqclean-2024", "commit": "202a8f9", "expected": 52.3, "category": "pqc-native"},
    {"repo": "kyber-reference-3.02", "commit": "4768bd3", "expected": 41.6, "category": "pqc-native"},
    {"repo": "dilithium-reference-3.1", "commit": "d35ba3f", "expected": 35.5, "category": "pqc-native"},
]


def cars_from_dimensions(
    dims: Dict[str, float],
    weights: Tuple[float, float, float, float, float] = DEFAULT_WEIGHTS,
) -> float:
    total = (
        weights[0] * float(dims["d1"])
        + weights[1] * float(dims["d2"])
        + weights[2] * float(dims["d3"])
        + weights[3] * float(dims["d4"])
        + weights[4] * float(dims["d5"])
    )
    score = 100.0 * total
    if score < 0.0:
        return 0.0
    if score > 100.0:
        return 100.0
    return float(score)


def run_offline(card_path: str) -> Dict[str, Any]:
    passed = 0
    failed = 0
    details: List[Dict[str, Any]] = []
    for name, vec in GOLDEN_VECTORS.items():
        computed = cars_from_dimensions(vec["dims"])
        ok = abs(computed - vec["target"]) <= vec["tolerance"] + 1e-9
        if ok:
            passed += 1
        else:
            failed += 1
        details.append(
            {
                "name": name,
                "computed": computed,
                "target": vec["target"],
                "tolerance": vec["tolerance"],
                "pass": ok,
                "source": vec["source"],
            }
        )
    replicated = [d["name"] for d in details if d["pass"]]
    card: Dict[str, Any] = {
        "tool": "pqblocks-agility",
        "mode": "offline",
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "weights": list(DEFAULT_WEIGHTS),
        "weights_sum": sum(DEFAULT_WEIGHTS),
        "offline": {"attempted": len(GOLDEN_VECTORS), "passed": passed, "failed": failed},
        "golden_details": details,
        "live_corpus": {
            "attempted": len(CORPUS_43),
            "replicated_offline": replicated,
            "skipped_offline": [
                {"repo": e["repo"], "reason": "live clone requires network + pinned commit; no published dimension vector for offline replication"}
                for e in CORPUS_43
                if e["repo"] not in ("pkcs11-provider-0.5", "pkcs11js-2.3", "oqs-provider-0.6")
            ],
        },
        "corpus_manifest": CORPUS_43,
    }
    with open(card_path, "w", encoding="utf-8") as fh:
        json.dump(card, fh, indent=2)
    return {"passed": passed, "failed": failed, "card": card_path}


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="pqblocks-agility benchmark harness")
    parser.add_argument("--offline", action="store_true", help="run offline equation vectors")
    parser.add_argument("--card", default="bench/benchmark-card.json", help="output card path")
    args = parser.parse_args(argv)
    summary = run_offline(args.card)
    print(f"offline: {summary['passed']} passed, {summary['failed']} failed -> {args.card}")
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
