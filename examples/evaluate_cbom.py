"""Example: Evaluate CARS agility score from a CycloneDX 1.6 CBOM."""
import json
import tempfile
from pathlib import Path

from pqblocks_agility.cbom import parse_cbom
from pqblocks_agility.cli import compute_cars_score

# Sample CycloneDX 1.6 CBOM with hybrid and classical components
sample_cbom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
    "version": 1,
    "components": [
        {
            "type": "cryptographic-asset",
            "name": "ML-KEM-768",
            "properties": [
                {"name": "pqblocks-scan.algorithm", "value": "ML-KEM-768"},
                {"name": "pqblocks-scan.grade", "value": "A"},
                {"name": "pqblocks-scan.quantum_vulnerable", "value": "false"},
            ],
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "parameterSetIdentifier": "768",
                },
            },
        },
        {
            "type": "cryptographic-asset",
            "name": "RSA-2048",
            "properties": [
                {"name": "pqblocks-scan.algorithm", "value": "RSA-2048"},
                {"name": "pqblocks-scan.grade", "value": "F"},
                {"name": "pqblocks-scan.quantum_vulnerable", "value": "true"},
            ],
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "parameterSetIdentifier": "2048",
                },
            },
        },
    ],
}

with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
    json.dump(sample_cbom, fh)
    temp_path = fh.name

try:
    cbom = parse_cbom(temp_path)
    score, dimensions = compute_cars_score(cbom)
    print(f"CARS score: {score:.1f} / 100.0")
    print(f"Dimensions: {dimensions}")
    assert 0.0 <= score <= 100.0, "Score must be in [0, 100]"
    assert all(k in dimensions for k in ("d1", "d2", "d3", "d4", "d5"))
    print("check passed: True")
finally:
    Path(temp_path).unlink(missing_ok=True)
