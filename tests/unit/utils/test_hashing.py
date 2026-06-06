"""Tests for shared hashing helpers."""

from __future__ import annotations

from pysymex.utils.hashing import (
    STABLE_DIGEST_ALGORITHM,
    stable_digest_hex,
)


def test_stable_digest_is_deterministic_256_bit_hex() -> None:
    first = stable_digest_hex(b"payload")
    second = stable_digest_hex(b"payload")

    assert STABLE_DIGEST_ALGORITHM == "blake2b-256"
    assert first == second
    assert len(first) == 64
    assert first != stable_digest_hex(b"changed")
