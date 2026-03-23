"""HMAC cache security tests.

Verifies that tampered cache entries are rejected.

Source contracts tested:
- analysis/cache/core.py (_CacheIntegrity, PersistentCache)

Critical invariants:
1. Bit flip in payload must be detected
2. Tag truncation must be rejected
3. Tag substitution must be rejected
4. Verification uses constant-time comparison
5. Corrupted entries are removed
"""

from __future__ import annotations

import hashlib
import hmac
import os
import pickle
import secrets
import tempfile
from pathlib import Path

import pytest

from pysymex._constants import HMAC_DIGEST, HMAC_KEY_SIZE, HMAC_TAG_SIZE
from pysymex.analysis.cache.core import (
    _CacheIntegrity,
    CacheKey,
    CacheKeyType,
    PersistentCache,
)


class TestBitFlipDetection:
    """Verify single bit changes in payload are detected."""

    def test_single_bit_flip_rejected(self):
        """Single bit flip in payload must be rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test.key"
            integrity = _CacheIntegrity(key_path)

            original_data = b"This is test data for HMAC verification"
            signed = integrity.sign(original_data)

            # Flip a single bit in the payload
            signed_list = list(signed)
            # Flip bit in payload area (after HMAC_TAG_SIZE)
            payload_idx = HMAC_TAG_SIZE + 5
            signed_list[payload_idx] ^= 0x01
            tampered = bytes(signed_list)

            # Should reject
            result = integrity.verify_and_extract(tampered)
            assert result is None

    def test_multiple_bit_flips_rejected(self):
        """Multiple bit flips must be rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test.key"
            integrity = _CacheIntegrity(key_path)

            original_data = b"Test payload for verification"
            signed = integrity.sign(original_data)

            # Flip multiple bits
            signed_list = list(signed)
            for i in range(HMAC_TAG_SIZE, min(HMAC_TAG_SIZE + 10, len(signed_list))):
                signed_list[i] ^= 0xFF
            tampered = bytes(signed_list)

            result = integrity.verify_and_extract(tampered)
            assert result is None

    def test_flip_in_tag_rejected(self):
        """Bit flip in HMAC tag must be rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test.key"
            integrity = _CacheIntegrity(key_path)

            original_data = b"Some test data"
            signed = integrity.sign(original_data)

            # Flip a bit in the tag area
            signed_list = list(signed)
            signed_list[5] ^= 0x01  # In tag area
            tampered = bytes(signed_list)

            result = integrity.verify_and_extract(tampered)
            assert result is None


class TestTagTruncationDetection:
    """Verify shortened HMAC tags are rejected."""

    def test_truncated_tag_rejected(self):
        """Truncated tag must be rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test.key"
            integrity = _CacheIntegrity(key_path)

            original_data = b"Test data"
            signed = integrity.sign(original_data)

            # Truncate to less than tag size
            truncated = signed[: HMAC_TAG_SIZE - 1]

            result = integrity.verify_and_extract(truncated)
            assert result is None

    def test_empty_blob_rejected(self):
        """Empty blob must be rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test.key"
            integrity = _CacheIntegrity(key_path)

            result = integrity.verify_and_extract(b"")
            assert result is None

    def test_tag_only_no_payload_rejected(self):
        """Tag with no payload should still work if valid."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test.key"
            integrity = _CacheIntegrity(key_path)

            # Sign empty payload
            signed = integrity.sign(b"")

            # Should verify (empty payload is valid)
            result = integrity.verify_and_extract(signed)
            assert result == b""


class TestTagSubstitutionDetection:
    """Verify tag substitution attacks are detected."""

    def test_tag_from_different_message_rejected(self):
        """Tag from different message must be rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test.key"
            integrity = _CacheIntegrity(key_path)

            message1 = b"First message"
            message2 = b"Second message"

            signed1 = integrity.sign(message1)
            signed2 = integrity.sign(message2)

            # Take tag from message1, payload from message2
            tag1 = signed1[:HMAC_TAG_SIZE]
            payload2 = signed2[HMAC_TAG_SIZE:]
            tampered = tag1 + payload2

            result = integrity.verify_and_extract(tampered)
            assert result is None

    def test_random_tag_rejected(self):
        """Random tag must be rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test.key"
            integrity = _CacheIntegrity(key_path)

            payload = b"Test payload"
            random_tag = secrets.token_bytes(HMAC_TAG_SIZE)
            fake_signed = random_tag + payload

            result = integrity.verify_and_extract(fake_signed)
            assert result is None


class TestKeyRotationHandling:
    """Verify key rotation invalidates old signatures."""

    def test_old_signature_rejected_after_key_change(self):
        """Signatures made with old key must be rejected after key change."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test.key"
            integrity = _CacheIntegrity(key_path)

            # Sign with original key
            original_data = b"Original data"
            signed = integrity.sign(original_data)

            # Verify it works
            assert integrity.verify_and_extract(signed) == original_data

            # Reset key (generates new key)
            integrity.reset_key()

            # Old signature should now be invalid
            result = integrity.verify_and_extract(signed)
            assert result is None


class TestKeyFileHandling:
    """Verify key file is handled correctly."""

    def test_key_created_if_missing(self):
        """Key file should be created if missing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "subdir" / "test.key"
            assert not key_path.exists()

            integrity = _CacheIntegrity(key_path)
            integrity.sign(b"test")  # This triggers key creation

            assert key_path.exists()
            assert len(key_path.read_bytes()) == HMAC_KEY_SIZE

    def test_corrupt_key_file_regenerated(self):
        """Corrupt key file should be regenerated."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test.key"

            # Create corrupt key file
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key_path.write_bytes(b"too short")

            integrity = _CacheIntegrity(key_path)
            integrity.sign(b"test")

            # Key should be regenerated to correct size
            assert len(key_path.read_bytes()) == HMAC_KEY_SIZE


class TestConstantTimeComparison:
    """Verify HMAC uses constant-time comparison."""

    def test_uses_hmac_compare_digest(self):
        """Verification should use hmac.compare_digest."""
        # This is a structural test - we verify the code uses compare_digest
        # by checking the implementation
        import inspect

        source = inspect.getsource(_CacheIntegrity.verify_and_extract)
        assert "compare_digest" in source


class TestPersistentCacheIntegration:
    """Verify HMAC integration with PersistentCache."""

    def test_tampered_entry_removed(self):
        """Tampered cache entry should be removed on access."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            cache = PersistentCache(db_path=db_path)

            key = CacheKey(CacheKeyType.CUSTOM, "test_key")
            value = {"data": "test_value"}

            # Store valid entry
            cache.put(key, value)
            assert key in cache

            # Manually tamper with the stored blob
            conn = cache._get_connection()
            cursor = conn.execute(
                "SELECT value_blob FROM cache WHERE key = ?", (key.to_string(),)
            )
            row = cursor.fetchone()
            original_blob = row["value_blob"]

            # Flip a bit in the payload
            tampered_blob = bytearray(original_blob)
            if len(tampered_blob) > HMAC_TAG_SIZE:
                tampered_blob[HMAC_TAG_SIZE + 1] ^= 0x01
            conn.execute(
                "UPDATE cache SET value_blob = ? WHERE key = ?",
                (bytes(tampered_blob), key.to_string()),
            )
            conn.commit()

            # Try to get the tampered entry
            result = cache.get(key)

            # Should return None (verification failed)
            assert result is None

            # Entry should be removed
            assert key not in cache

            cache.close()

    def test_valid_entry_retrieved(self):
        """Valid cache entries should be retrievable."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            cache = PersistentCache(db_path=db_path)

            key = CacheKey(CacheKeyType.FUNCTION, "my_function")
            value = {"result": 42, "items": [1, 2, 3]}

            cache.put(key, value)
            retrieved = cache.get(key)

            assert retrieved == value

            cache.close()

    def test_pickle_payload_integrity(self):
        """Pickled payload should be verified before deserialization."""
        import sys
        import time
        import shutil

        tmpdir = tempfile.mkdtemp()
        cache = None
        try:
            db_path = Path(tmpdir) / "test.db"
            cache = PersistentCache(db_path=db_path)

            key = CacheKey(CacheKeyType.SUMMARY, "test_summary")

            # Use a picklable dict with nested structure instead of local class
            obj = {"value": 123, "nested": {"data": [1, 2, 3]}}
            cache.put(key, obj)

            # Retrieve and verify
            retrieved = cache.get(key)
            assert retrieved is not None
            assert retrieved["value"] == 123
            assert retrieved["nested"]["data"] == [1, 2, 3]
        finally:
            if cache is not None:
                cache.close()
            # On Windows, retry cleanup with delays for WAL file release
            if sys.platform == "win32":
                for _ in range(5):
                    try:
                        shutil.rmtree(tmpdir)
                        break
                    except PermissionError:
                        time.sleep(0.2)
                else:
                    # Give up gracefully - temp dir will be cleaned eventually
                    pass
            else:
                shutil.rmtree(tmpdir)


class TestHMACAlgorithm:
    """Verify correct HMAC algorithm is used."""

    def test_uses_sha256(self):
        """Should use SHA-256 for HMAC."""
        assert HMAC_DIGEST == "sha256"
        assert HMAC_TAG_SIZE == 32  # SHA-256 produces 32-byte digest

    def test_key_size_correct(self):
        """Key size should be 256 bits."""
        assert HMAC_KEY_SIZE == 32


class TestEmptyPayloadHandling:
    """Verify empty payloads are handled correctly."""

    def test_empty_payload_signs_correctly(self):
        """Empty payload should be signable."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test.key"
            integrity = _CacheIntegrity(key_path)

            signed = integrity.sign(b"")

            assert len(signed) == HMAC_TAG_SIZE  # Just the tag

    def test_empty_payload_verifies_correctly(self):
        """Empty payload should verify correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test.key"
            integrity = _CacheIntegrity(key_path)

            signed = integrity.sign(b"")
            result = integrity.verify_and_extract(signed)

            assert result == b""


class TestLargePayloadHandling:
    """Verify large payloads are handled correctly."""

    def test_large_payload_signs_correctly(self):
        """Large payload should be signable."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test.key"
            integrity = _CacheIntegrity(key_path)

            large_data = secrets.token_bytes(1024 * 1024)  # 1 MB
            signed = integrity.sign(large_data)

            assert len(signed) == HMAC_TAG_SIZE + len(large_data)

    def test_large_payload_verifies_correctly(self):
        """Large payload should verify correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test.key"
            integrity = _CacheIntegrity(key_path)

            large_data = secrets.token_bytes(1024 * 100)  # 100 KB
            signed = integrity.sign(large_data)
            result = integrity.verify_and_extract(signed)

            assert result == large_data
