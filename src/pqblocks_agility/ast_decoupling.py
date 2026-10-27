"""
AST Decoupling Heuristics (Slice feature 3).
Implements the IS_DECOUPLED predicate and dimension d3 calculation per Spec §3.2 & §3.3.
"""

from __future__ import annotations

import ast
import re
from typing import Optional, List
from pqblocks_agility.cbom import CBOM, CBOMComponent

CONFIG_EXTENSIONS = (".yaml", ".yml", ".json", ".toml", ".ini", ".env", ".conf", ".cfg")
HARDCODED_KEY_PATTERNS = [
    re.compile(r"-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----"),
    re.compile(r"b['\"][0-9a-fA-F]{32,}['\"]"),
    re.compile(r"b['\"][0-9a-zA-Z+/=]{32,}['\"]"),
]

def is_decoupled(component: CBOMComponent, source_code: Optional[str] = None) -> bool:
    """Evaluate if a cryptographic asset is decoupled from application logic.
    
    Condition (a): Zero cryptographic keys hardcoded.
    Condition (b): Algorithm replaceable via policy/configuration change without recompilation.
    Condition (c): Key rotation feasible operationally without service downtime.
    """
    loc = (component.location or "").lower()
    file_part = loc.split(":")[0] if ":" in loc else loc

    # Rule 1: Config file locations are configurable/replaceable by definition
    if any(file_part.endswith(ext) for ext in CONFIG_EXTENSIONS):
        return True

    # Rule 2: If source code is provided, inspect for hardcoded keys and provider abstraction
    if source_code:
        for pattern in HARDCODED_KEY_PATTERNS:
            if pattern.search(source_code):
                return False
        
        # AST analysis: check if primitive is called directly or via an abstracted provider/release pipeline
        try:
            tree = ast.parse(source_code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    # Direct inline constructor calls like AES.new, RSA.generate without wrapper
                    if node.func.attr in ("new", "generate") and isinstance(node.func.value, ast.Name):
                        if node.func.value.id in ("AES", "RSA", "DES", "ARC4"):
                            return False
        except Exception:
            pass

    # Rule 3: Legacy/quantum-vulnerable assets directly in code are tightly coupled by default
    if component.quantum_vulnerable:
        return False

    # Default for PQC or modern components without hardcoded locations
    return True

def compute_d3(cbom: CBOM) -> float:
    """Calculate the d3 Architectural Decoupling dimension score in [0.0, 1.0].
    
    Formula:
    d3 = (1 / |I|) * sum(1 for a in I if IS_DECOUPLED(a))
    Empty inventory yields 0.0 per Edge Case E6.
    """
    if not cbom.components:
        return 0.0

    decoupled_count = sum(1 for c in cbom.components if is_decoupled(c))
    return round(decoupled_count / len(cbom.components), 4)
