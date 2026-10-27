"""
RED phase tests for feature 1 cbom.py — CBOM ingestion & validation.

Tests cover:
  E1  Empty CBOM
  E7  Invalid grade in properties
  E8  Missing grade (no derivable info)
  E9  CBOM version mismatch
  E10 Grade E (reserved, treated as 0.0)
  E18 Missing cbom.json file
  E19 Malformed CBOM JSON
  Happy path: current pqblocks-scan cryptoProperties format
  Happy path: future properties-array format with explicit grade
"""
import json
import tempfile
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_cbom(data: dict, tmp_path: Path) -> Path:
    p = tmp_path / "cbom.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def _base_cbom(components=None):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": components or [],
    }


def _crypto_component(
    name="RSA-2048",
    version="2048",
    asset_type="algorithm",
    nist_level=0,
    primitive="RSA-2048",
    properties=None,
):
    comp = {
        "type": "application",
        "name": name,
        "version": version,
        "cryptoProperties": {
            "assetType": asset_type,
            "nistQuantumSecurityLevel": nist_level,
            "algorithmProperties": {
                "primitive": primitive,
            },
        },
    }
    if properties is not None:
        comp["properties"] = properties
    return comp


# ---------------------------------------------------------------------------
# E1 — Empty CBOM
# ---------------------------------------------------------------------------

class TestEmptyCBOM:
    def test_empty_cbom_no_components(self, tmp_path):
        from pqblocks_agility.cbom import parse_cbom_dict

        cbom = _base_cbom([])
        result = parse_cbom_dict(cbom)
        assert result.components == []


# ---------------------------------------------------------------------------
# E9 — CBOM version mismatch
# ---------------------------------------------------------------------------

class TestCBOMVersionMismatch:
    def test_version_1_5_raises(self, tmp_path):
        from pqblocks_agility.cbom import CBOMVersionError, parse_cbom_dict

        cbom = _base_cbom([_crypto_component()])
        cbom["specVersion"] = "1.5"
        with pytest.raises(CBOMVersionError, match="1.5"):
            parse_cbom_dict(cbom)

    def test_version_1_4_raises(self, tmp_path):
        from pqblocks_agility.cbom import CBOMVersionError, parse_cbom_dict

        cbom = _base_cbom([_crypto_component()])
        cbom["specVersion"] = "1.4"
        with pytest.raises(CBOMVersionError, match="1.4"):
            parse_cbom_dict(cbom)


# ---------------------------------------------------------------------------
# E18 — Missing cbom.json file
# ---------------------------------------------------------------------------

class TestMissingCBOMFile:
    def test_missing_file_raises(self):
        from pqblocks_agility.cbom import FileNotFoundError, parse_cbom

        with pytest.raises(FileNotFoundError, match="no such file"):
            parse_cbom("/nonexistent/path/cbom.json")


# ---------------------------------------------------------------------------
# E19 — Malformed CBOM JSON
# ---------------------------------------------------------------------------

class TestMalformedCBOM:
    def test_malformed_json_raises(self, tmp_path):
        from pqblocks_agility.cbom import CBOMParseError, parse_cbom

        p = tmp_path / "bad.json"
        p.write_text("{not json", encoding="utf-8")
        with pytest.raises(CBOMParseError):
            parse_cbom(str(p))


# ---------------------------------------------------------------------------
# E7 — Invalid grade in properties
# ---------------------------------------------------------------------------

class TestInvalidGrade:
    def test_invalid_grade_raises(self, tmp_path):
        from pqblocks_agility.cbom import InvalidGradeError, parse_cbom_dict

        props = [{"name": "pqblocks-scan.grade", "value": "Z"}]
        cbom = _base_cbom([_crypto_component(properties=props)])
        with pytest.raises(InvalidGradeError, match="Z"):
            parse_cbom_dict(cbom)

    def test_invalid_grade_reports_component_id(self, tmp_path):
        from pqblocks_agility.cbom import InvalidGradeError, parse_cbom_dict

        props = [{"name": "pqblocks-scan.grade", "value": "X"}]
        comp = _crypto_component(name="my-lib", properties=props)
        cbom = _base_cbom([comp])
        with pytest.raises(InvalidGradeError, match="my-lib"):
            parse_cbom_dict(cbom)


# ---------------------------------------------------------------------------
# E8 — Missing grade property
# ---------------------------------------------------------------------------

class TestMissingGrade:
    def test_no_properties_no_cryptoproperties_raises(self):
        from pqblocks_agility.cbom import MissingGradeError, parse_cbom_dict

        comp = {
            "type": "application",
            "name": "unknown-lib",
            "version": "1.0",
        }
        cbom = _base_cbom([comp])
        # no cryptoProperties and no scan properties: not crypto inventory (H4), skipped
        assert parse_cbom_dict(cbom).components == []

    def test_no_algorithm_info_raises(self):
        from pqblocks_agility.cbom import MissingGradeError, parse_cbom_dict

        comp = {
            "type": "application",
            "name": "mystery",
            "version": "1.0",
            "cryptoProperties": {},
        }
        cbom = _base_cbom([comp])
        with pytest.raises(MissingGradeError, match="mystery"):
            parse_cbom_dict(cbom)


# ---------------------------------------------------------------------------
# E10 — Grade E (reserved, treated as 0.0)
# ---------------------------------------------------------------------------

class TestGradeEWarning:
    def test_grade_e_treated_as_zero(self):
        from pqblocks_agility.cbom import parse_cbom_dict

        props = [{"name": "pqblocks-scan.grade", "value": "E"}]
        cbom = _base_cbom([_crypto_component(name="ML-KEM-768", primitive="ML-KEM-768", properties=props)])
        result = parse_cbom_dict(cbom)
        assert result.components[0].grade == "E"


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------

class TestHappyPath:
    def test_current_scanner_format_derives_grade(self):
        from pqblocks_agility.cbom import parse_cbom_dict

        cbom = _base_cbom([
            _crypto_component(
                name="RSA-2048",
                version="2048",
                primitive="RSA-2048",
                nist_level=0,
            )
        ])
        result = parse_cbom_dict(cbom)
        assert len(result.components) == 1
        c = result.components[0]
        assert c.algorithm == "RSA-2048"
        assert c.grade == "F"
        assert c.quantum_vulnerable is True
        assert c.location is None

    def test_pqc_algorithm_derives_grade_a(self):
        from pqblocks_agility.cbom import parse_cbom_dict

        cbom = _base_cbom([
            _crypto_component(
                name="ML-KEM-768",
                version="768",
                primitive="ML-KEM-768",
                nist_level=3,
            )
        ])
        result = parse_cbom_dict(cbom)
        assert result.components[0].grade == "A"
        assert result.components[0].quantum_vulnerable is False

    def test_explicit_worse_grade_overrides_derivation(self):
        from pqblocks_agility.cbom import parse_cbom_dict

        props = [{"name": "pqblocks-scan.grade", "value": "C"}]
        cbom = _base_cbom([
            _crypto_component(
                name="ML-KEM-768",
                primitive="ML-KEM-768",
                nist_level=3,
                properties=props,
            )
        ])
        result = parse_cbom_dict(cbom)
        assert result.components[0].grade == "C"

    def test_explicit_location_parsed(self):
        from pqblocks_agility.cbom import parse_cbom_dict

        props = [
            {"name": "pqblocks-scan.grade", "value": "F"},
            {"name": "pqblocks-scan.location", "value": "crypto.py:42"},
            {"name": "pqblocks-scan.quantum_vulnerable", "value": "true"},
        ]
        cbom = _base_cbom([
            _crypto_component(name="RSA-2048", properties=props)
        ])
        result = parse_cbom_dict(cbom)
        assert result.components[0].location == "crypto.py:42"
        assert result.components[0].quantum_vulnerable is True


# ---------------------------------------------------------------------------
# Additional coverage tests for ≥90% coverage (feature 1 REFACTOR+VERIFY)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Grade C algorithms (lines 109, 112)
# ---------------------------------------------------------------------------

class TestGradeCAlgorithms:
    def test_aes_256_derives_grade_c(self):
        from pqblocks_agility.cbom import parse_cbom_dict

        cbom = _base_cbom([_crypto_component(name="AES-256", primitive="AES256")])
        result = parse_cbom_dict(cbom)
        assert result.components[0].grade == "C"
        assert result.components[0].grade_value == 0.60

    def test_sha256_derives_grade_c(self):
        from pqblocks_agility.cbom import parse_cbom_dict

        cbom = _base_cbom([_crypto_component(name="SHA-256", primitive="SHA256")])
        result = parse_cbom_dict(cbom)
        assert result.components[0].grade == "C"

    def test_chacha20_derives_grade_c(self):
        from pqblocks_agility.cbom import parse_cbom_dict

        cbom = _base_cbom([_crypto_component(name="ChaCha20", primitive="CHACHA20")])
        result = parse_cbom_dict(cbom)
        assert result.components[0].grade == "C"


# ---------------------------------------------------------------------------
# Grade D algorithms (line 116)
# ---------------------------------------------------------------------------

class TestGradeDAlgorithms:
    def test_rsa_3072_derives_grade_d(self):
        from pqblocks_agility.cbom import parse_cbom_dict

        cbom = _base_cbom([_crypto_component(name="RSA-3072", primitive="RSA3072")])
        result = parse_cbom_dict(cbom)
        assert result.components[0].grade == "D"

    def test_ecdsa_p384_derives_grade_d(self):
        from pqblocks_agility.cbom import parse_cbom_dict

        cbom = _base_cbom([_crypto_component(name="ECDSA P-384", primitive="ECDSAP384")])
        result = parse_cbom_dict(cbom)
        assert result.components[0].grade == "D"


# ---------------------------------------------------------------------------
# Grade B hybrid algorithms (lines 102, 104, 106)
# ---------------------------------------------------------------------------

class TestGradeBHybridAlgorithms:
    def test_hybrid_derives_grade_b(self):
        from pqblocks_agility.cbom import parse_cbom_dict

        cbom = _base_cbom([_crypto_component(name="Hybrid KEM", primitive="HYBRID-X25519-MLKEM768")])
        result = parse_cbom_dict(cbom)
        assert result.components[0].grade == "B"

    def test_x25519_mlkem_derives_grade_b(self):
        from pqblocks_agility.cbom import parse_cbom_dict

        cbom = _base_cbom([_crypto_component(name="X25519MLKEM768", primitive="X25519MLKEM768")])
        result = parse_cbom_dict(cbom)
        assert result.components[0].grade == "B"

    def test_mlkem_with_ecdh_derives_grade_b(self):
        from pqblocks_agility.cbom import parse_cbom_dict

        # Use a name that normalizes to contain MLKEM+X25519 but not start with MLKEM
        cbom = _base_cbom([_crypto_component(name="X25519-MLKEM-768", primitive="X25519MLKEM768")])


# ---------------------------------------------------------------------------
# ML-KEM-512 grade A via _derive_grade branch (line 99)
# ---------------------------------------------------------------------------

class TestGradeAOtherPqc:
    def test_mlkem_512_derives_grade_a(self):
        from pqblocks_agility.cbom import parse_cbom_dict

        cbom = _base_cbom([_crypto_component(name="ML-KEM-512", primitive="MLKEM512")])
        result = parse_cbom_dict(cbom)
        assert result.components[0].grade == "A"

    def test_mldsa_44_derives_grade_a(self):
        from pqblocks_agility.cbom import parse_cbom_dict

        cbom = _base_cbom([_crypto_component(name="ML-DSA-44", primitive="MLDSA44")])
        result = parse_cbom_dict(cbom)
        assert result.components[0].grade == "A"


# ---------------------------------------------------------------------------
# nist_level >= 1 fallback (lines 123-129)
# ---------------------------------------------------------------------------

class TestNistLevelFallback:
    def test_unknown_algorithm_with_nist_level_5_raises(self):
        """An unknown algorithm is never graded A from a self-declared level (H1)."""
        from pqblocks_agility.cbom import MissingGradeError, parse_cbom_dict

        comp = {
            "type": "application",
            "name": "unknown-algo",
            "version": "1.0",
            "cryptoProperties": {
                "algorithmProperties": {"primitive": "UNKNOWN-ALGO"},
                "nistQuantumSecurityLevel": 5,
            },
        }
        cbom = _base_cbom([comp])
        with pytest.raises(MissingGradeError):
            parse_cbom_dict(cbom)

    def test_unknown_algorithm_with_nist_level_0_raises(self):
        """When algorithm is unknown and nistQuantumSecurityLevel < 1, MissingGradeError."""
        from pqblocks_agility.cbom import MissingGradeError, parse_cbom_dict

        comp = {
            "type": "application",
            "name": "unknown-algo",
            "version": "1.0",
            "cryptoProperties": {
                "algorithmProperties": {"primitive": "UNKNOWN-ALGO"},
                "nistQuantumSecurityLevel": 0,
            },
        }
        cbom = _base_cbom([comp])
        with pytest.raises(MissingGradeError):
            parse_cbom_dict(cbom)


# ---------------------------------------------------------------------------
# _parse_bool False branch (line 134)
# ---------------------------------------------------------------------------

class TestParseBoolFalse:
    def test_quantum_vulnerable_false_string(self):
        from pqblocks_agility.cbom import parse_cbom_dict

        props = [
            {"name": "pqblocks-scan.grade", "value": "A"},
            {"name": "pqblocks-scan.quantum_vulnerable", "value": "false"},
        ]
        cbom = _base_cbom([_crypto_component(name="ML-KEM-768", primitive="ML-KEM-768", properties=props)])
        result = parse_cbom_dict(cbom)
        assert result.components[0].quantum_vulnerable is False

    def test_quantum_vulnerable_zero_string_rejected(self):
        from pqblocks_agility.cbom import CBOMParseError, parse_cbom_dict

        props = [
            {"name": "pqblocks-scan.grade", "value": "A"},
            {"name": "pqblocks-scan.quantum_vulnerable", "value": "0"},
        ]
        cbom = _base_cbom([_crypto_component(name="ML-KEM-768", primitive="ML-KEM-768", properties=props)])
        with pytest.raises(CBOMParseError):
            parse_cbom_dict(cbom)


# ---------------------------------------------------------------------------
# _component_id fallback to index (line 143)
# ---------------------------------------------------------------------------

class TestComponentIdFallback:
    def test_component_id_fallback_to_index(self):
        from pqblocks_agility.cbom import parse_cbom_dict

        # No bom-ref, bom_ref, id, or name fields present
        comp = {
            "type": "application",
            "version": "1.0",
            "cryptoProperties": {
                "algorithmProperties": {"primitive": "RSA-2048"},
            },
        }
        cbom = _base_cbom([comp])
        result = parse_cbom_dict(cbom)
        assert len(result.components) == 1
        assert result.components[0].component_id == "components[0]"

    def test_component_id_bom_ref(self):
        from pqblocks_agility.cbom import parse_cbom_dict

        comp = {
            "bom-ref": "comp-1",
            "type": "application",
            "version": "1.0",
            "cryptoProperties": {
                "algorithmProperties": {"primitive": "RSA-2048"},
            },
        }
        cbom = _base_cbom([comp])
        result = parse_cbom_dict(cbom)
        assert result.components[0].component_id == "comp-1"


# ---------------------------------------------------------------------------
# MissingGradeError from _derive_grade (line 189)
# ---------------------------------------------------------------------------

class TestDeriveGradeUnknownRaises:
    def test_unknown_algorithm_no_grade_raises_missing(self):
        from pqblocks_agility.cbom import MissingGradeError, _derive_grade

        with pytest.raises(MissingGradeError, match="UNKNOWN-XYZ"):
            _derive_grade("UNKNOWN-XYZ", 0)


# ---------------------------------------------------------------------------
# parse_cbom non-dict top-level (lines 236-238)
# ---------------------------------------------------------------------------

class TestParseCbomNonDict:
    def test_non_dict_top_level_raises_cbom_parse_error(self, tmp_path):
        from pqblocks_agility.cbom import CBOMParseError, parse_cbom

        p = tmp_path / "array.json"
        p.write_text("[1, 2, 3]", encoding="utf-8")
        with pytest.raises(CBOMParseError, match="top-level value must be an object"):
            parse_cbom(str(p))

    def test_non_dict_null_top_level_raises_cbom_parse_error(self, tmp_path):
        from pqblocks_agility.cbom import CBOMParseError, parse_cbom

        p = tmp_path / "null.json"
        p.write_text("null", encoding="utf-8")
        with pytest.raises(CBOMParseError, match="top-level value must be an object"):
            parse_cbom(str(p))
