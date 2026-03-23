"""Instruction cache correctness tests.

Verifies that instruction cache returns correct, consistent results.

Source contracts tested:
- instruction_cache.py (get_instructions, clear_cache)

Critical invariants:
1. Same code object returns same result
2. Different functions return different results
3. Cache is thread-safe
4. Dynamically generated code works correctly
"""

from __future__ import annotations

import dis
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

import pytest

from pysymex.core.instruction_cache import get_instructions, clear_cache


class TestSameCodeObjectSameResult:
    """Verify same code object always returns identical results."""

    def test_multiple_calls_same_result(self):
        """Multiple calls with same code object return identical tuples."""

        def sample_func(x: int) -> int:
            return x + 1

        result1 = get_instructions(sample_func.__code__)
        result2 = get_instructions(sample_func.__code__)
        result3 = get_instructions(sample_func.__code__)

        assert result1 is result2  # Same object (cached)
        assert result2 is result3

    def test_result_is_tuple(self):
        """Result must be a tuple (immutable)."""

        def func():
            pass

        result = get_instructions(func.__code__)
        assert isinstance(result, tuple)

    def test_contains_instruction_objects(self):
        """Result must contain dis.Instruction objects."""

        def func(x):
            return x * 2

        result = get_instructions(func.__code__)
        assert len(result) > 0
        for instr in result:
            assert isinstance(instr, dis.Instruction)

    def test_instructions_match_dis_module(self):
        """Cached instructions must match dis.get_instructions output."""

        def func(a, b):
            return a + b

        cached = get_instructions(func.__code__)
        direct = tuple(dis.get_instructions(func.__code__))

        assert len(cached) == len(direct)
        for c, d in zip(cached, direct):
            assert c.opname == d.opname
            assert c.arg == d.arg
            assert c.argval == d.argval


class TestDifferentFunctionsDifferentResults:
    """Verify different code objects return different results."""

    def test_different_functions_not_confused(self):
        """Different functions must return different instruction tuples."""

        def func_add(x):
            return x + 1

        def func_mul(x):
            return x * 2

        result_add = get_instructions(func_add.__code__)
        result_mul = get_instructions(func_mul.__code__)

        assert result_add is not result_mul
        assert result_add != result_mul

    def test_same_body_different_objects(self):
        """Functions with same body but different code objects are separate."""
        # Use exec to create genuinely different code objects
        # since CPython 3.11+ aggressively shares code objects for identical functions
        ns1: dict = {}
        ns2: dict = {}
        exec("def inner(x): return x + 1", ns1)
        exec("def inner(x): return x + 1", ns2)

        func1 = ns1["inner"]
        func2 = ns2["inner"]

        result1 = get_instructions(func1.__code__)
        result2 = get_instructions(func2.__code__)

        # exec-generated functions have different code objects
        assert func1.__code__ is not func2.__code__
        # Results should be equal in content
        assert result1 == result2


class TestDynamicallyGeneratedCode:
    """Verify dynamically generated code works correctly."""

    def test_exec_generated_function(self):
        """exec-generated functions should work."""
        namespace: dict = {}
        exec("def dynamic_func(x): return x ** 2", namespace)
        func = namespace["dynamic_func"]

        result = get_instructions(func.__code__)

        assert isinstance(result, tuple)
        assert len(result) > 0

    def test_compile_generated_code(self):
        """compile-generated code objects should work."""
        code = compile("x + y", "<test>", "eval")

        result = get_instructions(code)

        assert isinstance(result, tuple)
        assert len(result) > 0

    def test_lambda_functions(self):
        """Lambda functions should work."""
        f = lambda x: x * 2

        result = get_instructions(f.__code__)

        assert isinstance(result, tuple)
        assert len(result) > 0


class TestNestedAndClosureFunctions:
    """Verify nested and closure functions work correctly."""

    def test_nested_function(self):
        """Nested function code objects should work."""

        def outer():
            def inner(x):
                return x + 1

            return inner

        inner_func = outer()
        result = get_instructions(inner_func.__code__)

        assert isinstance(result, tuple)
        assert len(result) > 0

    def test_closure_function(self):
        """Closure functions should work."""

        def make_adder(n):
            def adder(x):
                return x + n

            return adder

        add5 = make_adder(5)
        add10 = make_adder(10)

        result5 = get_instructions(add5.__code__)
        result10 = get_instructions(add10.__code__)

        # Same code structure (both are adder)
        # The code objects are actually the same for closures
        assert result5 is result10  # Same code object


class TestCacheClearBehavior:
    """Verify cache clear works correctly."""

    def test_clear_cache_recomputes(self):
        """After clear, next call should recompute instructions."""

        def func(x):
            return x

        result1 = get_instructions(func.__code__)
        clear_cache()
        result2 = get_instructions(func.__code__)

        # Results should be equal in content
        assert result1 == result2
        # But may be different objects after clear
        # (cache miss forces recomputation)

    def test_clear_does_not_crash(self):
        """Clear should not crash even when empty."""
        clear_cache()
        clear_cache()  # Double clear should be fine


class TestThreadSafety:
    """Verify cache is thread-safe."""

    def test_concurrent_access_same_function(self):
        """Multiple threads accessing same function should be safe."""

        def target_func(x):
            return x * 2 + 1

        results = []
        errors = []

        def worker():
            try:
                for _ in range(100):
                    result = get_instructions(target_func.__code__)
                    results.append(result)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        # All results should be the same object (cached)
        first = results[0]
        for r in results:
            assert r is first

    def test_concurrent_access_different_functions(self):
        """Multiple threads accessing different functions should be safe."""
        funcs = []
        for i in range(20):
            namespace: dict = {}
            exec(f"def func_{i}(x): return x + {i}", namespace)
            funcs.append(namespace[f"func_{i}"])

        results: dict[int, list] = {i: [] for i in range(len(funcs))}
        errors = []

        def worker(func_idx):
            try:
                for _ in range(50):
                    result = get_instructions(funcs[func_idx].__code__)
                    results[func_idx].append(result)
            except Exception as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker, i % len(funcs)) for i in range(100)]
            for f in futures:
                f.result()

        assert not errors

        # Each function's results should be consistent
        for func_idx, func_results in results.items():
            if func_results:
                first = func_results[0]
                for r in func_results:
                    assert r is first


class TestCacheStatistics:
    """Verify cache statistics work correctly."""

    def test_cache_info_available(self):
        """Cache info should be available via functools.lru_cache."""
        clear_cache()

        def func(x):
            return x

        # First call - cache miss
        get_instructions(func.__code__)

        # Second call - cache hit
        get_instructions(func.__code__)

        info = get_instructions.cache_info()
        assert info.hits >= 1
        assert info.misses >= 1


class TestEdgeCases:
    """Test edge cases."""

    def test_empty_function(self):
        """Empty function should work."""

        def empty():
            pass

        result = get_instructions(empty.__code__)
        assert isinstance(result, tuple)

    def test_single_return_function(self):
        """Function with only return should work."""

        def returns_none():
            return None

        result = get_instructions(returns_none.__code__)
        assert isinstance(result, tuple)

    def test_complex_function(self):
        """Complex function with many opcodes should work."""

        def complex_func(x, y, z):
            result = 0
            for i in range(x):
                if i % 2 == 0:
                    result += y
                else:
                    result -= z
                try:
                    result //= (i + 1)
                except ZeroDivisionError:
                    pass
            return result

        result = get_instructions(complex_func.__code__)
        assert isinstance(result, tuple)
        assert len(result) > 10  # Should have many instructions

    def test_generator_function(self):
        """Generator function should work."""

        def gen(n):
            for i in range(n):
                yield i

        result = get_instructions(gen.__code__)
        assert isinstance(result, tuple)

    def test_async_function(self):
        """Async function should work."""

        async def async_func():
            return 42

        result = get_instructions(async_func.__code__)
        assert isinstance(result, tuple)
