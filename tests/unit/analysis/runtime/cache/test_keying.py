"""Tests for active cache keying helpers."""

from __future__ import annotations

from pysymex._internal.analysis.runtime.cache.keying import cache_hit_rate, hash_function


def test_cache_hit_rate() -> None:
    assert cache_hit_rate(0, 0) == 0.0
    assert cache_hit_rate(3, 1) == 0.75


def test_hash_function() -> None:
    def my_func() -> None:
        pass

    h1 = hash_function("my_func", my_func.__code__, "sig1")
    h2 = hash_function("my_func", my_func.__code__, "sig1")
    h3 = hash_function("my_func2", my_func.__code__, "sig1")
    assert h1 == h2
    assert h1 != h3

    h4 = hash_function("my_func", b"code_bytes", "sig2")
    h5 = hash_function("my_func", b"code_bytes", "sig2")
    assert h4 == h5
    assert len(h1) == 64


def test_hash_function_distinguishes_local_variable_layout() -> None:
    def first(arg: object) -> object:
        return arg

    def second(other: object) -> object:
        return other

    assert first.__code__.co_code == second.__code__.co_code
    assert first.__code__.co_consts == second.__code__.co_consts

    h1 = hash_function("same_name", first.__code__)
    h2 = hash_function("same_name", second.__code__)

    assert h1 != h2


def test_hash_function_is_stable_for_nested_code_constants() -> None:
    source = """
def outer():
    def inner():
        return 1
    return inner()
"""
    first_namespace: dict[str, object] = {}
    second_namespace: dict[str, object] = {}
    exec(compile(source, "module_a.py", "exec"), first_namespace)
    exec(compile(source, "module_b.py", "exec"), second_namespace)

    first_outer = first_namespace["outer"]
    second_outer = second_namespace["outer"]
    assert callable(first_outer)
    assert callable(second_outer)

    h1 = hash_function("outer", first_outer.__code__)
    h2 = hash_function("outer", second_outer.__code__)

    assert h1 == h2
