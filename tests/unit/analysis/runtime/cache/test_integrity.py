"""Tests for persistent cache BLAKE2b integrity."""

from __future__ import annotations

from pathlib import Path

from pysymex.analysis.runtime.cache.integrity import (
    BLAKE2B_TAG_SIZE,
    CacheIntegrity,
)


class TestCacheIntegrity:
    """Keyed BLAKE2b sign/verify round trips."""

    def test_sign_and_verify_round_trip(self, tmp_path: Path) -> None:
        integrity = CacheIntegrity(tmp_path / "cache.key")
        payload = b"pickled-value"
        signed = integrity.sign("cache-key", payload)
        assert len(signed) == BLAKE2B_TAG_SIZE + len(payload)
        assert integrity.verify_and_extract("cache-key", signed) == payload

    def test_verify_rejects_tampered_blob(self, tmp_path: Path) -> None:
        integrity = CacheIntegrity(tmp_path / "cache.key")
        signed = bytearray(integrity.sign("cache-key", b"safe"))
        signed[-1] ^= 0xFF
        assert integrity.verify_and_extract("cache-key", bytes(signed)) is None

    def test_verify_rejects_wrong_cache_key(self, tmp_path: Path) -> None:
        integrity = CacheIntegrity(tmp_path / "cache.key")
        signed = integrity.sign("cache-key", b"safe")
        assert integrity.verify_and_extract("other-key", signed) is None
