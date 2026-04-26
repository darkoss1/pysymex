import pysymex.core.cache


def test_get_instructions() -> None:
    """Scenario: identical code object lookup twice; expected same cached tuple object."""
    pysymex.core.cache.clear_cache()

    def sample() -> int:
        return 1

    first = pysymex.core.cache.get_instructions(sample.__code__)
    second = pysymex.core.cache.get_instructions(sample.__code__)
    assert first is second


def test_clear_cache() -> None:
    """Scenario: cache has entries then clear is called; expected empty cache size."""

    def sample() -> int:
        return 2

    _ = pysymex.core.cache.get_instructions(sample.__code__)
    pysymex.core.cache.clear_cache()
    assert pysymex.core.cache.get_instructions.cache_info().currsize == 0
