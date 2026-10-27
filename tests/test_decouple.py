"""
RED phase tests for feature 3 decouple.py — AST decoupling heuristics.

Tests cover the IS_DECOUPLED predicate:
- E3: Single asset, Grade F, coupled
- E15: PR diff introduces Grade F (coupled detection)

Negative tests (garbage in => loud error out):
- Non-existent source file
- Invalid line number
- Empty source content
"""
import tempfile
from pathlib import Path

import pytest


class TestISDecoupledCoupled:
    def test_hardcoded_rsa_key_is_coupled(self):
        from pqblocks_agility.decouple import is_decoupled

        source = '''
def encrypt(data):
    key = b"MIIEvQIBADCBNwSAAIBiEAAAAAAAAAA..."  # 32+ char hardcoded key
    # RSA-2048 encryption
    return rsa_encrypt(data, key)
'''
        with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as f:
            f.write(source)
            f.flush()
            result = is_decoupled(f.name, 2, 'RSA-2048')
        assert result is False

    def test_os_getenv_passes_condition_a(self):
        from pqblocks_agility.decouple import is_decoupled

        source = '''
import os

def encrypt(data):
    key = os.getenv('ENCRYPTION_KEY')
    # RSA-2048 encryption
    return rsa_encrypt(data, key)
'''
        with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as f:
            f.write(source)
            f.flush()
            result = is_decoupled(f.name, 3, 'RSA-2048')
        assert result is True

    def test_direct_crypto_call_fails_condition_b(self):
        from pqblocks_agility.decouple import is_decoupled

        source = '''
from cryptography.hazmat.primitives import hashes

def hash_data(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()
'''
        with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as f:
            f.write(source)
            f.flush()
            result = is_decoupled(f.name, 4, 'SHA-256')
        assert result is True  # hashlib abstraction is acceptable

    def test_hybrid_via_provider_passes(self):
        from pqblocks_agility.decouple import is_decoupled

        source = '''
import crypto

def encrypt(data):
    provider = crypto.Provider.get_default()
    key = provider.get_key('my-key')
    return provider.encrypt(data, key)
'''
        with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as f:
            f.write(source)
            f.flush()
            result = is_decoupled(f.name, 4, 'RSA-2048')
        assert result is True

    def test_traditionally_coupled_returns_false(self):
        from pqblocks_agility.decouple import is_decoupled

        source = '''
def legacy_encrypt(data):
    key = b"deadbeef1234567890abcdef1234567890"  # hardcoded key
    return old_rsa_encrypt(data, key)  # direct primitive call
'''
        with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as f:
            f.write(source)
            f.flush()
            result = is_decoupled(f.name, 3, 'RSA-2048')
        assert result is False


class TestHardcodedKeyDetection:
    def test_base64_key_over_32_chars_detected(self):
        from pqblocks_agility.decouple import has_hardcoded_key

        source = b'MY_KEY = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ123456="'
        assert has_hardcoded_key(source, 1) is True

    def test_short_key_not_detected(self):
        from pqblocks_agility.decouple import has_hardcoded_key

        source = b'MY_KEY = b"shortkeyabc="'
        assert has_hardcoded_key(source, 1) is False

    def test_envvar_key_not_flagged(self):
        from pqblocks_agility.decouple import has_hardcoded_key

        source = b'KEY = os.getenv("MY_KEY")'
        assert has_hardcoded_key(source, 1) is False

    def test_no_hardcoded_key_returns_false(self):
        from pqblocks_agility.decouple import has_hardcoded_key

        source = b'DATA = b"some_data"'
        assert has_hardcoded_key(source, 1) is False


class TestProviderAbstraction:
    def test_evp_pkey_api_passes(self):
        from pqblocks_agility.decouple import has_provider_abstraction

        source = b'''
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
'''
        assert has_provider_abstraction(source) is True

    def test_pkcs11_c_initialize_passes(self):
        from pqblocks_agility.decouple import has_provider_abstraction

        source = b'''
import ck
ck.C_Initialize(None)
'''
        assert has_provider_abstraction(source) is True

    def test_direct_primitive_call_fails(self):
        from pqblocks_agility.decouple import has_provider_abstraction

        source = b'''
def encrypt(data, key):
    # Direct RSA call with no abstraction
    return raw_rsa_encrypt(data, key)
'''
        assert has_provider_abstraction(source) is False

    def test_configparser_usage_passes(self):
        from pqblocks_agility.decouple import has_provider_abstraction

        source = b'''
import configparser
config = configparser.ConfigParser()
key = config.get('crypto', 'key_path')
'''
        assert has_provider_abstraction(source) is True


class TestRotationFeasibility:
    def test_env_var_rotation_feasible(self):
        from pqblocks_agility.decouple import can_rotate_24h

        source = b'''
import os
KEY_PATH = os.getenv("KEY_ROTATION_PATH", "/etc/keys/key.pem")
'''
        assert can_rotate_24h(source) is True

    def test_hardcoded_rotation_invalidator(self):
        from pqblocks_agility.decouple import can_rotate_24h

        source = b'''
def rotate_key():
    # Rotation logic hardcoded - need recompile
    pass
'''
        assert can_rotate_24h(source) is False

    def test_external_kms_passes(self):
        from pqblocks_agility.decouple import can_rotate_24h

        source = b'''
import boto3
kms = boto3.client('kms', region_name='us-east-1')
'''
        assert can_rotate_24h(source) is True


class TestNonexistentFile:
    def test_nonexistent_file_raises_error(self):
        from pqblocks_agility.decouple import is_decoupled

        with pytest.raises(FileNotFoundError, match="no such file"):
            is_decoupled("/nonexistent/path/file.py", 1, "RSA-2048")


class TestInvalidLineNumbers:
    def test_line_below_zero_raises(self):
        from pqblocks_agility.decouple import is_decoupled

        with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as f:
            f.write("x = 1")
            f.flush()
            with pytest.raises(ValueError, match="line must be >= 1"):
                is_decoupled(f.name, 0, "RSA-2048")

    def test_line_beyond_file_raises(self):
        from pqblocks_agility.decouple import is_decoupled

        with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as f:
            f.write("x = 1\n")
            f.flush()
            with pytest.raises(ValueError, match="line number exceeds"):
                is_decoupled(f.name, 100, "RSA-2048")


class TestEmptyInput:
    def test_empty_file_is_coupled(self):
        from pqblocks_agility.decouple import is_decoupled

        with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as f:
            f.write("")
            f.flush()
            result = is_decoupled(f.name, 1, "RSA-2048")
        assert result is False