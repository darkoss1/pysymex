"""Tests for instruction_cache module.

These tests verify that:
1. Instruction caching returns correct results
2. Cache invalidation works properly
3. Cache is thread-safe
4. Cache handles edge cases (empty functions, large functions)
"""

from __future__ import annotations

import dis
import gc
import sys
import threading
import types
from typing import Any

import pytest

from pysymex.core.instruction_cache import clear_cache, get_instructions


class TestInstructionCacheBasics:
    """Basic instruction cache functionality tests."""

    def test_returns_tuple(self):
        """get_instructions should return a tuple."""
        def simple():
            return 42

        result = get_instructions(simple.__code__)
        assert isinstance(result, tuple)

    def test_returns_instructions(self):
        """get_instructions should return Instruction objects."""
        def simple():
            x = 1
            return x

        result = get_instructions(simple.__code__)
        assert len(result) > 0
        assert all(isinstance(instr, dis.Instruction) for instr in result)

    def test_matches_dis_get_instructions(self):
        """Cache result should match dis.get_instructions."""
        def sample():
            x = 1
            y = 2
            return x + y

        cached = get_instructions(sample.__code__)
        direct = tuple(dis.get_instructions(sample.__code__))

        assert len(cached) == len(direct)
        for c, d in zip(cached, direct):
            assert c.opname == d.opname
            assert c.argval == d.argval


class TestInstructionCacheCaching:
    """Tests for actual caching behavior."""

    def test_same_code_same_object(self):
        """Same code object should return same tuple object."""
        def func():
            return 1

        result1 = get_instructions(func.__code__)
        result2 = get_instructions(func.__code__)

        assert result1 is result2  # Same object reference

    def test_different_code_different_result(self):
        """Different code objects should return different results."""
        def func1():
            return 1

        def func2():
            return 2

        result1 = get_instructions(func1.__code__)
        result2 = get_instructions(func2.__code__)

        assert result1 is not result2

    def test_cache_hit_after_first_call(self):
        """Second call should be a cache hit."""
        def func():
            x = 1
            y = 2
            z = x + y
            return z

        clear_cache()

        # First call
        get_instructions(func.__code__)
        info_after_first = get_instructions.cache_info()

        # Second call
        get_instructions(func.__code__)
        info_after_second = get_instructions.cache_info()

        assert info_after_second.hits > info_after_first.hits


class TestInstructionCacheClear:
    """Tests for cache clearing."""

    def test_clear_cache_resets(self):
        """clear_cache should reset the cache."""
        def func():
            return 42

        # Populate cache
        get_instructions(func.__code__)
        info_before = get_instructions.cache_info()
        assert info_before.currsize > 0

        # Clear
        clear_cache()
        info_after = get_instructions.cache_info()

        assert info_after.currsize == 0
        assert info_after.hits == 0
        assert info_after.misses == 0

    def test_usable_after_clear(self):
        """Cache should be fully functional after clear."""
        def func():
            return 1

        get_instructions(func.__code__)
        clear_cache()

        # Should work normally
        result = get_instructions(func.__code__)
        assert len(result) > 0


class TestInstructionCacheEdgeCases:
    """Edge case tests."""

    def test_empty_function(self):
        """Empty function (just pass) should be handled."""
        def empty():
            pass

        result = get_instructions(empty.__code__)
        assert isinstance(result, tuple)
        # Even 'pass' compiles to at least RESUME and RETURN_CONST/RETURN_VALUE

    def test_lambda(self):
        """Lambda functions should work."""
        f = lambda x: x * 2

        result = get_instructions(f.__code__)
        assert isinstance(result, tuple)

    def test_nested_function(self):
        """Nested function code should work."""
        def outer():
            def inner():
                return 42
            return inner

        inner_func = outer()
        result = get_instructions(inner_func.__code__)
        assert isinstance(result, tuple)

    def test_class_method(self):
        """Class method code should work."""
        class MyClass:
            def method(self):
                return self

        result = get_instructions(MyClass.method.__code__)
        assert isinstance(result, tuple)

    def test_generator_function(self):
        """Generator function code should work."""
        def gen():
            yield 1
            yield 2

        result = get_instructions(gen.__code__)
        assert isinstance(result, tuple)
        # Should contain YIELD_VALUE
        opnames = [instr.opname for instr in result]
        assert "YIELD_VALUE" in opnames or "RETURN_GENERATOR" in opnames

    def test_async_function(self):
        """Async function code should work."""
        async def async_func():
            return 42

        result = get_instructions(async_func.__code__)
        assert isinstance(result, tuple)

    def test_comprehension(self):
        """Comprehension code objects should work."""
        # Comprehensions create their own code objects
        code = compile("[x for x in range(10)]", "<test>", "eval")
        # The actual comprehension code is in co_consts
        for const in code.co_consts:
            if isinstance(const, types.CodeType):
                result = get_instructions(const)
                assert isinstance(result, tuple)
                break


class TestInstructionCacheLargeCode:
    """Tests with larger code objects."""

    def test_large_function(self):
        """Large function with many instructions."""
        # Create function with many operations
        source = "def large():\n"
        source += "    x = 0\n"
        for i in range(100):
            source += f"    x = x + {i}\n"
        source += "    return x\n"

        local_ns: dict = {}
        exec(source, {}, local_ns)
        large = local_ns["large"]

        result = get_instructions(large.__code__)
        assert isinstance(result, tuple)
        assert len(result) > 100


class TestInstructionCacheThreadSafety:
    """Thread-safety tests."""

    def test_concurrent_access(self):
        """Concurrent access should be safe."""
        def func():
            x = 1
            y = 2
            return x + y

        errors: list[Exception] = []
        results: list[tuple[dis.Instruction, ...]] = []

        def worker():
            try:
                for _ in range(100):
                    result = get_instructions(func.__code__)
                    results.append(result)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread safety violation: {errors}"
        # All results should be the same object
        assert len(set(id(r) for r in results)) == 1

    def test_concurrent_access_different_functions(self):
        """Concurrent access with different functions."""
        functions = []
        for i in range(10):
            local_ns: dict = {}
            exec(f"def func_{i}():\n    return {i}", {}, local_ns)
            functions.append(local_ns[f"func_{i}"])

        errors: list[Exception] = []

        def worker(thread_id):
            try:
                for _ in range(50):
                    for f in functions:
                        get_instructions(f.__code__)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread safety violation: {errors}"


class TestInstructionCacheTupleImmutability:
    """Tests that returned tuple is immutable."""

    def test_cannot_modify_returned_tuple(self):
        """Returned tuple should not be modifiable."""
        def func():
            return 1

        result = get_instructions(func.__code__)

        with pytest.raises(TypeError):
            result[0] = None  # type: ignore

        # Tuples don't have append method - verify this
        assert not hasattr(result, 'append') or hasattr(tuple, 'append')


class TestInstructionCacheMemory:
    """Memory behavior tests."""

    def test_cache_bounded_by_maxsize(self):
        """Cache should not grow beyond maxsize."""
        # Create many unique functions to exceed cache size
        clear_cache()

        for i in range(3000):  # Exceed maxsize of 2048
            local_ns: dict = {}
            exec(f"def unique_func_{i}():\n    return {i}", {}, local_ns)
            func = local_ns[f"unique_func_{i}"]
            get_instructions(func.__code__)

        info = get_instructions.cache_info()
        assert info.currsize <= info.maxsize

    def test_lru_eviction(self):
        """LRU eviction should work correctly."""
        clear_cache()

        functions = []
        for i in range(2100):  # Create more than maxsize
            local_ns: dict = {}
            exec(f"def evict_test_{i}():\n    return {i}", {}, local_ns)
            functions.append(local_ns[f"evict_test_{i}"])

        # Call all functions once
        for f in functions:
            get_instructions(f.__code__)

        # Early functions may have been evicted
        info = get_instructions.cache_info()
        assert info.currsize <= 2048  # maxsize
