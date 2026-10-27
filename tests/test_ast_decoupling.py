"""
Unit tests for AST Decoupling Heuristics (pqblocks-agility).
Tests IS_DECOUPLED predicate and d3 dimension calculation per Spec §3.2 & §3.3.
"""
import pytest
from pqblocks_agility.cbom import CBOM, CBOMComponent
from pqblocks_agility.ast_decoupling import is_decoupled, compute_d3

def test_config_location_is_decoupled():
    comp = CBOMComponent(
        component_id="1",
        name="ML-KEM-768",
        version="1.0",
        algorithm="ML-KEM-768",
        grade="A",
        grade_value=1.0,
        location="config.yaml:3",
        quantum_vulnerable=False,
    )
    assert is_decoupled(comp) is True

def test_hardcoded_source_is_not_decoupled():
    comp = CBOMComponent(
        component_id="2",
        name="RSA-2048",
        version="1.0",
        algorithm="RSA-2048",
        grade="F",
        grade_value=0.0,
        location="crypto.py:42",
        quantum_vulnerable=True,
    )
    assert is_decoupled(comp) is False

def test_worked_example_4_asset_repo():
    """Worked example from Spec §3.3: 4 assets, d3 should be exactly 0.50."""
    components = [
        CBOMComponent("1", "ML-KEM-768", "1.0", "ML-KEM-768", "A", 1.0, "config.yaml:3", False),
        CBOMComponent("2", "RSA-2048", "1.0", "RSA-2048", "F", 0.0, "crypto.py:42", True),
        CBOMComponent("3", "AES-256-GCM", "1.0", "AES-256-GCM", "C", 0.6, "config.yaml:7", False),
        CBOMComponent("4", "ECDH-P256", "1.0", "ECDH-P256", "F", 0.0, "legacy.py:15", True),
    ]
    cbom = CBOM(components=components)
    d3 = compute_d3(cbom)
    assert d3 == 0.50

def test_empty_cbom_d3_is_zero():
    """Edge Case E6: Empty inventory yields d3 = 0.0."""
    cbom = CBOM(components=[])
    assert compute_d3(cbom) == 0.0

def test_ast_source_decoupling_detection():
    """Test AST source code inspection for abstraction layer vs inline primitive instantiation."""
    source_decoupled = """
from my_crypto_provider import get_cipher

def encrypt(data):
    cipher = get_cipher()
    return cipher.encrypt(data)
"""
    comp = CBOMComponent("1", "AES-256-GCM", "1.0", "AES", "C", 0.6, "app.py:5", False)
    assert is_decoupled(comp, source_code=source_decoupled) is True

    source_coupled = """
from Crypto.Cipher import AES

def encrypt(data):
    key = b'0123456789abcdef0123456789abcdef' # hardcoded key
    cipher = AES.new(key, AES.MODE_GCM)
    return cipher.encrypt(data)
"""
    comp2 = CBOMComponent("2", "AES-256", "1.0", "AES", "F", 0.0, "app.py:5", True)
    assert is_decoupled(comp2, source_code=source_coupled) is False
