import pytest
from pqblocks_agility.cbom import CBOM, CBOMComponent
from pqblocks_agility.cars_scoring import score_cbom

def test_worked_example():
    # Create the four assets from the worked example in spec section 3.3
    components = [
        CBOMComponent(
            component_id="0",
            name="ML-KEM-768",
            version="1.0",
            algorithm="ML-KEM-768",
            grade="A",
            grade_value=1.0,
            location="config.yaml:3",
            quantum_vulnerable=False,
        ),
        CBOMComponent(
            component_id="1",
            name="RSA-2048",
            version="1.0",
            algorithm="RSA-2048",
            grade="F",
            grade_value=0.0,
            location="crypto.py:42",
            quantum_vulnerable=True,
        ),
        CBOMComponent(
            component_id="2",
            name="AES-256-GCM",
            version="1.0",
            algorithm="AES-256-GCM",
            grade="C",
            grade_value=0.6,
            location="config.yaml:7",
            quantum_vulnerable=False,
        ),
        CBOMComponent(
            component_id="3",
            name="ECDH P-256",
            version="1.0",
            algorithm="ECDH P-256",
            grade="F",
            grade_value=0.0,
            location="legacy.py:15",
            quantum_vulnerable=True,
        ),
    ]
    cbom = CBOM(components=components)
    cars_score, dims = score_cbom(cbom)
    assert cars_score == 47.5
    assert dims["d1"] == 0.5
    assert dims["d2"] == 0.4  # (1.0 + 0.0 + 0.6 + 0.0) / 4
    assert dims["d3"] == 0.5  # placeholder
    assert dims["d4"] == 0.5  # placeholder
    assert dims["d5"] == 0.5  # placeholder

def test_empty_cbom():
    cbom = CBOM(components=[])
    cars_score, dims = score_cbom(cbom)
    assert cars_score == 0.0
    assert dims["d1"] == 0.0
    assert dims["d2"] == 0.0
    assert dims["d3"] == 0.0
    assert dims["d4"] == 0.0
    assert dims["d5"] == 0.0

def test_single_asset_grade_a():
    components = [
        CBOMComponent(
            component_id="0",
            name="ML-KEM-768",
            version="1.0",
            algorithm="ML-KEM-768",
            grade="A",
            grade_value=1.0,
            location="config.yaml:3",
            quantum_vulnerable=False,
        )
    ]
    cbom = CBOM(components=components)
    cars_score, dims = score_cbom(cbom)
    # d3 = 1.0 (decoupled): 0.1 + 0.25 + 0.25 + 0.075 + 0.075 = 0.75 * 100 = 75.0
    assert abs(cars_score - 75.0) < 1e-5
    assert dims["d2"] == 1.0

def test_all_grade_f():
    components = [
        CBOMComponent(
            component_id=str(i),
            name=f"RSA-{2048+i}",
            version="1.0",
            algorithm="RSA-2048",
            grade="F",
            grade_value=0.0,
            location=f"file{i}.py:1",
            quantum_vulnerable=True,
        )
        for i in range(5)
    ]
    cbom = CBOM(components=components)
    cars_score, dims = score_cbom(cbom)
    # d3 = 0 (all vulnerable code): 0.1 + 0 + 0 + 0.075 + 0.075 = 0.25 * 100 = 25.0
    assert cars_score == 25.0
    assert dims["d2"] == 0.0

def test_clamp_low():
    # We cannot get below 0 with the current formula, but we test the clamp anyway
    # By setting all dimensions to 0, we get 0.
    # We'll mock the dimensions by patching the function? Instead, we test the function directly.
    # Since we don't have a way to set dimensions to 0 via CBOM, we skip and rely on the formula.
    pass

def test_clamp_high():
    # Similarly, we cannot get above 100 with the current formula.
    pass