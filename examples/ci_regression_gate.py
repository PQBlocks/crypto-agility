"""Example: CI/CD regression firewall and SARIF 2.1.0 telemetry export."""
import json
import tempfile
from pathlib import Path

from pqblocks_agility.cbom import parse_cbom
from pqblocks_agility.ci_gate import evaluate_gate

# CBOM with post-quantum and classical assets
cbom_data = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:6c361972-23c3-4d4b-9721-a47fa266184a",
    "version": 1,
    "components": [
        {
            "type": "cryptographic-asset",
            "name": "ML-KEM-1024",
            "properties": [
                {"name": "pqblocks-scan.algorithm", "value": "ML-KEM-1024"},
                {"name": "pqblocks-scan.grade", "value": "A"},
                {"name": "pqblocks-scan.quantum_vulnerable", "value": "false"},
            ],
        },
        {
            "type": "cryptographic-asset",
            "name": "AES-256-GCM",
            "properties": [
                {"name": "pqblocks-scan.algorithm", "value": "AES-256-GCM"},
                {"name": "pqblocks-scan.grade", "value": "C"},
                {"name": "pqblocks-scan.quantum_vulnerable", "value": "false"},
            ],
        },
    ],
}

with tempfile.TemporaryDirectory() as tmpdir:
    cbom_path = Path(tmpdir) / "cbom.json"
    sarif_path = Path(tmpdir) / "results.sarif"
    cbom_path.write_text(json.dumps(cbom_data), encoding="utf-8")

    cbom = parse_cbom(str(cbom_path))
    # Evaluate gate with minimum threshold 50.0 and SARIF export
    res = evaluate_gate(cbom, min_cars=50.0, sarif_out=str(sarif_path))

    print(f"Gate passed: {res['passed']}")
    print(f"CARS score: {res['cars_score']} (Tier: {res['tier']})")
    print(f"SARIF file written: {sarif_path.exists()}")

    assert res["passed"] is True
    assert res["exit_code"] == 0
    assert sarif_path.exists()
    sarif_doc = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif_doc["version"] == "2.1.0"
    print("check passed: True")
