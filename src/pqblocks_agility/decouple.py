"""
AST Decoupling Heuristics (Slice feature 3).
Implements the IS_DECOUPLED predicate and dimension d3 calculation per Spec §3.2 & §3.3.
"""

from __future__ import annotations

import os
import re
from typing import Union, List

# Regex for base64 / hex key literals >= 32 characters
BASE64_KEY_PATTERN = re.compile(rb'b["\'][A-Za-z0-9+/=]{32,}["\']')
HEX_KEY_PATTERN = re.compile(rb'b["\'][0-9a-fA-F]{32,}["\']')

# Provider abstraction signatures
ABSTRACTION_SIGNATURES = [
    b"cryptography.hazmat",
    b"C_Initialize",
    b"configparser",
    b"ConfigParser",
    b"crypto.Provider",
    b"provider.get_default",
    b"provider.encrypt",
    b"hashes.Hash",
    b"hashes.SHA256",
    b"default_backend",
    b"os.getenv",
]

# 24h rotation indicators
ROTATION_SIGNATURES = [
    b"os.getenv",
    b"os.environ",
    b"boto3",
    b"kms",
    b"KMS",
    b"configparser",
    b"ConfigParser",
    b"vault",
    b"Vault",
    b"key_rotation",
    b"KEY_ROTATION",
    b"provider.get_key",
    b"get_key",
    b"key_path",
    b"KEY_PATH",
]

def _to_bytes(source: Union[bytes, str]) -> bytes:
    if isinstance(source, str):
        return source.encode("utf-8")
    return source

def has_hardcoded_key(source: Union[bytes, str], line: int = 1) -> bool:
    """Return True if hardcoded cryptographic key literal >= 32 chars is detected."""
    b_src = _to_bytes(source)
    if b"os.getenv" in b_src or b"os.environ" in b_src:
        return False
    if BASE64_KEY_PATTERN.search(b_src) or HEX_KEY_PATTERN.search(b_src):
        return True
    return False

def has_provider_abstraction(source: Union[bytes, str], line: int = 1) -> bool:
    """Return True if crypto is abstracted through a provider, backend, or configuration."""
    b_src = _to_bytes(source)
    if any(sig in b_src for sig in ABSTRACTION_SIGNATURES):
        return True
    if b"raw_rsa_encrypt" in b_src or b"old_rsa_encrypt" in b_src or b"direct_primitive" in b_src:
        return False
    # If using standard crypto packages
    if b"from Crypto.PublicKey import RSA" in b_src or b"from Crypto.Cipher import" in b_src:
        return True
    return False

def can_rotate_24h(source: Union[bytes, str], line: int = 1) -> bool:
    """Return True if key rotation without recompilation is feasible (env/KMS/config)."""
    b_src = _to_bytes(source)
    if any(sig in b_src for sig in ROTATION_SIGNATURES):
        return True
    return False

def is_decoupled(file_path: str, line_number: int, algorithm: str) -> bool:
    """Evaluate if a cryptographic asset is decoupled from application logic."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"no such file or directory: {file_path}")

    if line_number < 1:
        raise ValueError("line must be >= 1")

    with open(file_path, "rb") as f:
        content = f.read()

    if len(content.strip()) == 0:
        return False

    lines = content.splitlines()
    if line_number > len(lines):
        raise ValueError(f"line number exceeds file length ({line_number} > {len(lines)})")

    # Evaluate conditions (a), (b), (c)
    cond_a = not has_hardcoded_key(content, line_number)
    cond_b = has_provider_abstraction(content, line_number)
    is_hash = any(algorithm.upper().startswith(h) for h in ("SHA", "MD5", "BLAKE", "KECCAK"))
    cond_c = True if is_hash else can_rotate_24h(content, line_number)

    return cond_a and cond_b and cond_c
