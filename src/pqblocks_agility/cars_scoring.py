"""CARS scoring engine (feature 2).

Implements the Costa (2026) CARS scoring model:
CARS(S) = 100 * sum(w_i * d_i(S)) for i=1..5
where w = (0.20, 0.25, 0.25, 0.15, 0.15) are fixed weights.

Dimensions:
- d1: Inventory Completeness (placeholder: 0.50 for non-empty, 0.0 for empty)
- d2: Algorithm Compliance (calculated from grade values)
- d3: Architectural Decoupling (ast_decoupling.compute_d3)
- d4: Toolchain Readiness (placeholder: 0.50 for non-empty, 0.0 for empty)
- d5: Governance & Compliance (placeholder: 0.50 for non-empty, 0.0 for empty)

d3 comes from ast_decoupling.compute_d3; d1, d4, d5 are scenario placeholders (0.50).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple

from pqblocks_agility.cbom import CBOM
from pqblocks_agility.ast_decoupling import compute_d3


WEIGHTS = (0.20, 0.25, 0.25, 0.15, 0.15)


class UnknownProfileError(ValueError):
    """Raised when an unknown weight profile is specified (E20)."""


WEIGHT_PROFILES: Dict[str, Tuple[float, float, float, float, float]] = {
    "default": WEIGHTS,
    "cloud-enterprise": WEIGHTS,
    "embedded-iot": (0.15, 0.20, 0.35, 0.15, 0.15),
}


def get_profile_weights(profile_name: str) -> Tuple[float, float, float, float, float]:
    norm = profile_name.strip().lower()
    if norm not in WEIGHT_PROFILES:
        raise UnknownProfileError(
            f"unknown weight profile {profile_name!r}; valid profiles: {list(WEIGHT_PROFILES.keys())}"
        )
    return WEIGHT_PROFILES[norm]


def compute_cars_score(
    cbom: CBOM,
    profile: str = "default",
    d1_mode: str = "scenario",
) -> Tuple[float, Dict[str, float]]:
    """The single CARS implementation used by the CLI and the Python API.

    Returns (CARS_score, {'d1'..'d5'}) with every dimension in [0, 1].
    """
    weights = get_profile_weights(profile)

    if not cbom.components:
        # Empty inventory: all dimensions zero per edge case E6
        return 0.0, {f"d{i}": 0.0 for i in range(1, 6)}

    if d1_mode == "empirical":
        d1 = min(1.0, round(len(cbom.components) / (1.3 * max(1, len(cbom.components))), 4))
    else:
        d1 = 0.50
    d2 = sum(c.grade_value for c in cbom.components) / len(cbom.components)
    dimensions = {"d1": d1, "d2": d2, "d3": compute_d3(cbom), "d4": 0.50, "d5": 0.50}

    weighted_sum = sum(w * dimensions[f"d{i+1}"] for i, w in enumerate(weights))
    return max(0.0, min(100.0, round(100.0 * weighted_sum, 6))), dimensions


def score_cbom(cbom: CBOM) -> Tuple[float, Dict[str, float]]:
    """Default-profile CARS score; alias of compute_cars_score."""
    return compute_cars_score(cbom)


def get_weights() -> Tuple[float, ...]:
    """Return the fixed CARS weights."""
    return WEIGHTS


def validate_weights() -> bool:
    """Validate that weights sum to 1.0 (for internal consistency)."""
    return abs(sum(WEIGHTS) - 1.0) < 1e-9
