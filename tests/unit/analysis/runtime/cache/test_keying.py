"""Tests for cache keys and hash helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from pysymex.analysis.runtime.cache.keying import (
    CacheKey,
    CacheKeyType,
    hash_bytecode,
    hash_dict,
    hash_file,
    hash_function,
)


class TestCacheKeyType:
    """Test suite for pysymex.analysis.runtime.cache.keying.CacheKeyType."""

    def test_initialization(self) -> None:
        assert CacheKeyType.FUNCTION.name == "FUNCTION"


class TestCacheKey:
    """Test suite for pysymex.analysis.runtime.cache.keying.CacheKey."""

    def test_to_string(self) -> None:
        key = CacheKey(CacheKeyType.FUNCTION, "my_func", "1.5")
        assert key.to_string() == "FUNCTION:my_func:1.5"

    def test_from_string(self) -> None:
        key = CacheKey.from_string("MODULE:my_module:2.0")
        assert key.key_type == CacheKeyType.MODULE
        assert key.identifier == "my_module"
        assert key.version == "2.0"

        key2 = CacheKey.from_string("CUSTOM:my_custom")
        assert key2.key_type == CacheKeyType.CUSTOM
        assert key2.identifier == "my_custom"
        assert key2.version == "1.0"

        with pytest.raises(ValueError):
            CacheKey.from_string("invalid_format")


def test_hash_bytecode() -> None:
    b1 = b"abc"
    b2 = b"abc"
    assert hash_bytecode(b1) == hash_bytecode(b2)
    assert hash_bytecode(b1) != hash_bytecode(b"def")
    assert len(hash_bytecode(b1)) == 64


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


def test_hash_file(tmp_path: Path) -> None:
    file = tmp_path / "test.txt"
    file.write_bytes(b"content")
    h1 = hash_file(file)
    file.write_bytes(b"content")
    h2 = hash_file(file)
    file.write_bytes(b"changed")
    h3 = hash_file(file)
    assert h1 == h2
    assert h1 != h3
    assert len(h1) == 64


def test_hash_dict() -> None:
    d1 = {"a": 1, "b": 2}
    d2 = {"b": 2, "a": 1}
    assert hash_dict(d1) == hash_dict(d2)
    assert hash_dict(d1) != hash_dict({"a": 1})
    assert len(hash_dict(d1)) == 64
