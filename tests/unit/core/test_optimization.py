import z3

import pysymex.core.optimization as mod


class TestCacheStats:
    def test_hit_rate(self) -> None:
        stats = mod.CacheStats(hits=1, misses=1)
        assert stats.hit_rate == 50.0


class TestConstraintCache:
    def test_get(self) -> None:
        cache = mod.ConstraintCache(max_size=4)
        constraints = [z3.Bool("c")]
        cache.put(constraints, True, None, 0.1)
        assert cache.get(constraints) is not None

    def test_put(self) -> None:
        cache = mod.ConstraintCache(max_size=1)
        cache.put([z3.Bool("a")], True, None, 0.1)
        assert len(cache) == 1

    def test_clear(self) -> None:
        cache = mod.ConstraintCache(max_size=2)
        cache.put([z3.Bool("a")], True, None, 0.1)
        cache.clear()
        assert len(cache) == 0


def test_get_constraint_cache() -> None:
    cache = mod.get_constraint_cache()
    assert isinstance(cache, mod.ConstraintCache)


def test_cached_is_satisfiable() -> None:
    assert mod.cached_is_satisfiable([z3.BoolVal(True)])
