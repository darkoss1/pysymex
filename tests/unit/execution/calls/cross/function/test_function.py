import z3

from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.calls.cross.function.summary.cache.core import FunctionSummaryCache
from pysymex._internal.execution.calls.cross.function.summary.cache.core import (
    FunctionSummaryCache as FunctionSummaryCacheOwner,
)
from pysymex._internal.execution.calls.cross.function.summary.cache.keys import compute_summary_key


class TestFunctionSummaryCache:
    """Test suite for pysymex._internal.execution.calls.cross.function.summary.cache.FunctionSummaryCache."""

    def test_public_export_points_to_direct_owner(self) -> None:
        """The package import surface stays wired to the cache storage owner."""
        assert FunctionSummaryCache is FunctionSummaryCacheOwner

    def test_get(self) -> None:
        """Test get behavior."""
        cache = FunctionSummaryCache()
        assert cache.get("f", [], []) is None
        assert cache.misses == 1

    def test_put(self) -> None:
        """Test put behavior."""
        cache = FunctionSummaryCache()
        sym = z3.Int("x")
        cache.put("f", [1], [sym > 0], "summary1")
        res = cache.get("f", [1], [sym > 0])
        assert res == "summary1"
        assert cache.hits == 1

    def test_zero_size_cache_does_not_store_summary(self) -> None:
        """Zero-size summary caches are valid but never retain entries."""
        cache = FunctionSummaryCache(max_size=0)

        cache.put("f", [1], [], "summary1")

        assert cache.get("f", [1], []) is None
        assert len(cache.cache) == 0

    def test_summary_cache_eviction_is_lru(self) -> None:
        """Bounded summaries evict the least recently used entry."""
        cache = FunctionSummaryCache(max_size=2)

        cache.put("f1", [1], [], "summary1")
        cache.put("f2", [2], [], "summary2")
        assert cache.get("f1", [1], []) == "summary1"
        cache.put("f3", [3], [], "summary3")

        assert cache.get("f1", [1], []) == "summary1"
        assert cache.get("f2", [2], []) is None
        assert cache.get("f3", [3], []) == "summary3"

    def test_compute_key_canonicalizes_symbolic_argument_names(self) -> None:
        """Symbolic argument names should not affect summary key canonicalization."""
        cache = FunctionSummaryCache()
        x1, _ = SymbolicValue.symbolic_int("x")
        y1, _ = SymbolicValue.symbolic_int("y")
        key1 = cache.compute_key("f", [x1, y1], [x1.z3_int > y1.z3_int])

        x2, _ = SymbolicValue.symbolic_int("left")
        y2, _ = SymbolicValue.symbolic_int("right")
        key2 = cache.compute_key("f", [x2, y2], [x2.z3_int > y2.z3_int])

        assert key1 == key2

    def test_compute_key_delegates_to_canonical_key_owner(self) -> None:
        """The storage class delegates key construction to the direct key owner."""
        cache = FunctionSummaryCache()
        x, _ = SymbolicValue.symbolic_int("x")
        constraints = [x.z3_int > 0]

        assert cache.compute_key("f", [x], constraints) == compute_summary_key(
            "f", [x], constraints
        )

    def test_compute_key_distinguishes_concrete_symbolic_values(self) -> None:
        """Concrete SymbolicValue payloads must not collide when unconstrained."""
        cache = FunctionSummaryCache()
        one = SymbolicValue.from_const(1)
        two = SymbolicValue.from_const(2)

        key1 = cache.compute_key("f", [one], [])
        key2 = cache.compute_key("f", [two], [])

        assert key1 != key2

    def test_compute_key_distinguishes_none_symbolic_value_from_unknown_symbolic_value(
        self,
    ) -> None:
        """None carries no _constant_value payload, so it needs explicit key coverage."""
        cache = FunctionSummaryCache()
        none_value = SymbolicValue.from_const(None)
        unknown, _ = SymbolicValue.symbolic("maybe_none")

        key1 = cache.compute_key("f", [none_value], [])
        key2 = cache.compute_key("f", [unknown], [])

        assert key1 != key2

    def test_compute_key_ignores_constraints_when_arguments_are_concrete(self) -> None:
        """Concrete-only calls keep current behavior and hash constraints as zero."""
        cache = FunctionSummaryCache()
        x = z3.Int("x")
        key1 = cache.compute_key("f", [1, "a"], [x > 0])
        key2 = cache.compute_key("f", [1, "a"], [x < 0, x != 3])

        assert key1 == key2
