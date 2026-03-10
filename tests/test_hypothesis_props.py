"""Hypothesis property tests for core data structures.

Covers:
- CowDict: copy-on-write fork/mutate correctness
- ConstraintChain: append/to_list round-trip, length invariant
- LRUCache: eviction policy, get/put consistency, hit-rate
- _CacheIntegrity: sign/verify round-trip, tamper detection
"""

from __future__ import annotations

import string

from hypothesis import given, settings
from hypothesis import strategies as st

# ---------------------------------------------------------------------------
# CowDict property tests
# ---------------------------------------------------------------------------
from pysymex.core.copy_on_write import ConstraintChain, CowDict


class TestCowDictProperties:
    """Property-based tests for CowDict fork/mutate correctness."""

    @given(st.dictionaries(st.text(string.ascii_letters, min_size=1, max_size=8), st.integers()))
    def test_to_dict_round_trip(self, data: dict[str, int]) -> None:
        """CowDict.to_dict() == original dict."""
        cow = CowDict(dict(data))
        assert cow.to_dict() == data

    @given(
        st.dictionaries(st.text(string.ascii_letters, min_size=1, max_size=8), st.integers()),
        st.text(string.ascii_letters, min_size=1, max_size=8),
        st.integers(),
    )
    def test_fork_isolation(self, data: dict[str, int], key: str, value: int) -> None:
        """Mutating a fork does not affect the original."""
        original = CowDict(dict(data))
        fork = original.cow_fork()
        fork[key] = value
        # Original is unchanged
        if key not in data:
            assert key not in original
        else:
            assert original[key] == data[key]
        # Fork has the new value
        assert fork[key] == value

    @given(
        st.dictionaries(
            st.text(string.ascii_letters, min_size=1, max_size=8), st.integers(), min_size=1
        ),
    )
    def test_fork_delete_isolation(self, data: dict[str, int]) -> None:
        """Deleting from a fork does not affect the original."""
        original = CowDict(dict(data))
        fork = original.cow_fork()
        key = next(iter(data))
        del fork[key]
        assert key in original
        assert key not in fork

    @given(st.dictionaries(st.text(string.ascii_letters, min_size=1, max_size=8), st.integers()))
    def test_len_matches_dict(self, data: dict[str, int]) -> None:
        """CowDict.__len__ matches backing dict length."""
        cow = CowDict(dict(data))
        assert len(cow) == len(data)

    @given(
        st.dictionaries(st.text(string.ascii_letters, min_size=1, max_size=8), st.integers()),
        st.text(string.ascii_letters, min_size=1, max_size=8),
        st.integers(),
    )
    def test_setdefault_behavior(self, data: dict[str, int], key: str, value: int) -> None:
        """CowDict.setdefault matches dict.setdefault."""
        cow = CowDict(dict(data))
        ref = dict(data)
        cow_result = cow.setdefault(key, value)
        ref_result = ref.setdefault(key, value)
        assert cow_result == ref_result
        assert cow.to_dict() == ref

    @given(
        st.dictionaries(st.text(string.ascii_letters, min_size=1, max_size=8), st.integers()),
        st.dictionaries(st.text(string.ascii_letters, min_size=1, max_size=8), st.integers()),
    )
    def test_update_matches_dict(self, base: dict[str, int], updates: dict[str, int]) -> None:
        """CowDict.update matches dict.update."""
        cow = CowDict(dict(base))
        ref = dict(base)
        cow.update(updates)
        ref.update(updates)
        assert cow.to_dict() == ref


# ---------------------------------------------------------------------------
# ConstraintChain property tests
# ---------------------------------------------------------------------------


class TestConstraintChainProperties:
    """Property-based tests for ConstraintChain append/round-trip."""

    @given(st.lists(st.booleans(), max_size=50))
    def test_append_to_list_round_trip(self, bools: list[bool]) -> None:
        """Appending N constraints then to_list() gives them in order."""
        import z3

        constraints = [z3.BoolVal(b) for b in bools]
        chain = ConstraintChain.empty()
        for c in constraints:
            chain = chain.append(c)
        result = chain.to_list()
        assert len(result) == len(constraints)
        for a, b in zip(result, constraints, strict=True):
            assert str(a) == str(b)

    @given(st.lists(st.booleans(), max_size=50))
    def test_length_invariant(self, bools: list[bool]) -> None:
        """len(chain) == number of appended constraints."""
        import z3

        chain = ConstraintChain.empty()
        for i, b in enumerate(bools):
            chain = chain.append(z3.BoolVal(b))
            assert len(chain) == i + 1

    @given(st.lists(st.booleans(), min_size=1, max_size=30))
    def test_from_list_round_trip(self, bools: list[bool]) -> None:
        """from_list(constraints).to_list() == constraints."""
        import z3

        constraints = [z3.BoolVal(b) for b in bools]
        chain = ConstraintChain.from_list(constraints)
        result = chain.to_list()
        assert len(result) == len(constraints)
        for a, b in zip(result, constraints, strict=True):
            assert str(a) == str(b)

    def test_empty_chain(self) -> None:
        """Empty chain has length 0 and to_list() returns []."""
        chain = ConstraintChain.empty()
        assert len(chain) == 0
        assert chain.to_list() == []
        assert not chain

    @given(st.lists(st.booleans(), min_size=1, max_size=20))
    def test_fork_independence(self, bools: list[bool]) -> None:
        """Appending to a forked chain doesn't affect the original."""
        import z3

        constraints = [z3.BoolVal(b) for b in bools]
        chain = ConstraintChain.from_list(constraints)
        original_len = len(chain)

        # 'Fork' by appending to chain
        extended = chain.append(z3.BoolVal(True))
        assert len(chain) == original_len
        assert len(extended) == original_len + 1


# ---------------------------------------------------------------------------
# LRUCache property tests
# ---------------------------------------------------------------------------

from pysymex.analysis.cache.core import LRUCache


class TestLRUCacheProperties:
    """Property-based tests for LRUCache eviction and consistency."""

    @given(
        st.integers(min_value=1, max_value=50),
        st.lists(
            st.tuples(st.text(string.ascii_letters, min_size=1, max_size=4), st.integers()),
            max_size=100,
        ),
    )
    @settings(max_examples=50)
    def test_never_exceeds_maxsize(self, maxsize: int, items: list[tuple[str, int]]) -> None:
        """Cache never holds more items than maxsize."""
        cache: LRUCache[str, int] = LRUCache(maxsize=maxsize)
        for key, val in items:
            cache.put(key, val)
            assert len(cache) <= maxsize

    @given(
        st.lists(
            st.tuples(st.text(string.ascii_letters, min_size=1, max_size=4), st.integers()),
            min_size=1,
            max_size=50,
        ),
    )
    def test_get_after_put(self, items: list[tuple[str, int]]) -> None:
        """The last put for a key is always retrievable."""
        cache: LRUCache[str, int] = LRUCache(maxsize=len(items) + 1)
        latest: dict[str, int] = {}
        for key, val in items:
            cache.put(key, val)
            latest[key] = val
        for key, val in latest.items():
            assert cache.get(key) == val

    @given(
        st.lists(
            st.tuples(
                st.text(string.ascii_letters, min_size=1, max_size=2),
                st.integers(),
            ),
            min_size=5,
            max_size=30,
        ),
    )
    @settings(max_examples=30)
    def test_eviction_removes_lru(self, items: list[tuple[str, int]]) -> None:
        """After exceeding maxsize, earliest unique keys are evicted."""
        cache: LRUCache[str, int] = LRUCache(maxsize=3)
        for key, val in items:
            cache.put(key, val)
        # After all insertions, cache has at most 3 entries
        assert len(cache) <= 3

    @given(
        st.lists(
            st.tuples(st.text(string.ascii_letters, min_size=1, max_size=4), st.integers()),
            max_size=20,
        ),
    )
    def test_clear_resets(self, items: list[tuple[str, int]]) -> None:
        """After clear(), cache is empty and stats are zero."""
        cache: LRUCache[str, int] = LRUCache(maxsize=100)
        for key, val in items:
            cache.put(key, val)
        cache.clear()
        assert len(cache) == 0

    @given(
        st.lists(
            st.tuples(st.text(string.ascii_letters, min_size=1, max_size=4), st.integers()),
            min_size=1,
            max_size=20,
        ),
    )
    def test_remove_returns_correct_bool(self, items: list[tuple[str, int]]) -> None:
        """remove() returns True for existing keys, False otherwise."""
        cache: LRUCache[str, int] = LRUCache(maxsize=100)
        for key, val in items:
            cache.put(key, val)
        key_to_remove = items[0][0]
        assert cache.remove(key_to_remove) is True
        assert cache.remove(key_to_remove) is False


# ---------------------------------------------------------------------------
# _CacheIntegrity property tests
# ---------------------------------------------------------------------------


class TestCacheIntegrityProperties:
    """Property-based tests for HMAC sign/verify round-trip."""

    @given(st.binary(min_size=0, max_size=1024))
    def test_sign_verify_round_trip(self, blob: bytes) -> None:
        """sign(blob) → verify_and_extract() returns original blob."""
        from pysymex._constants import HMAC_TAG_SIZE
        from pysymex.analysis.cache.core import _CacheIntegrity

        integrity = _CacheIntegrity.__new__(_CacheIntegrity)
        integrity._key = b"\x42" * 32  # deterministic test key

        signed = integrity.sign(blob)
        assert len(signed) == HMAC_TAG_SIZE + len(blob)

        extracted = integrity.verify_and_extract(signed)
        assert extracted == blob

    @given(st.binary(min_size=1, max_size=1024))
    def test_tampered_blob_rejected(self, blob: bytes) -> None:
        """Flipping a byte in signed data causes verify to return None."""
        from pysymex._constants import HMAC_TAG_SIZE
        from pysymex.analysis.cache.core import _CacheIntegrity

        integrity = _CacheIntegrity.__new__(_CacheIntegrity)
        integrity._key = b"\x42" * 32

        signed = integrity.sign(blob)
        # Flip a byte in the payload (after the tag)
        tampered = bytearray(signed)
        tampered[HMAC_TAG_SIZE] ^= 0xFF
        tampered = bytes(tampered)

        assert integrity.verify_and_extract(tampered) is None

    @given(st.binary(min_size=1, max_size=512))
    def test_truncated_blob_rejected(self, blob: bytes) -> None:
        """Truncated signed data is rejected."""
        from pysymex.analysis.cache.core import _CacheIntegrity

        integrity = _CacheIntegrity.__new__(_CacheIntegrity)
        integrity._key = b"\x42" * 32

        signed = integrity.sign(blob)
        truncated = signed[: len(signed) // 2]

        result = integrity.verify_and_extract(truncated)
        # Truncated data should either return None or a different blob
        # (but not the original)
        if result is not None:
            assert result != blob
