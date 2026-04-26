from __future__ import annotations

import pytest
import z3

from pysymex.contracts.compiler import (
    And_,
    Implies_,
    Not_,
    Or_,
    _FormulaCache,
    ContractCompiler,
    _formula_cache,
)


class TestAndCombinator:
    """Test suite for And_ in contracts/compiler.py."""

    def test_no_args_returns_true(self) -> None:
        """Verify that And_() returns z3.BoolVal(True)."""
        result = And_()
        assert z3.is_true(result)

    def test_one_arg_returns_arg(self) -> None:
        """Verify that And_(x) returns x."""
        x = z3.Bool("x")
        result = And_(x)
        assert result.eq(x)

    def test_multiple_args_returns_z3_and(self) -> None:
        """Verify that And_(x, y) returns z3.And(x, y)."""
        x = z3.Bool("x")
        y = z3.Bool("y")
        result = And_(x, y)
        assert result.decl().kind() == z3.Z3_OP_AND

    def test_handles_bools(self) -> None:
        """Verify that And_ handles python booleans."""
        x = z3.Bool("x")
        result = And_(True, x)
        assert result.decl().kind() == z3.Z3_OP_AND


class TestOrCombinator:
    """Test suite for Or_ in contracts/compiler.py."""

    def test_no_args_returns_false(self) -> None:
        """Verify that Or_() returns z3.BoolVal(False)."""
        result = Or_()
        assert z3.is_false(result)

    def test_one_arg_returns_arg(self) -> None:
        """Verify that Or_(x) returns x."""
        x = z3.Bool("x")
        result = Or_(x)
        assert result.eq(x)

    def test_multiple_args_returns_z3_or(self) -> None:
        """Verify that Or_(x, y) returns z3.Or(x, y)."""
        x = z3.Bool("x")
        y = z3.Bool("y")
        result = Or_(x, y)
        assert result.decl().kind() == z3.Z3_OP_OR

    def test_handles_bools(self) -> None:
        """Verify that Or_ handles python booleans."""
        x = z3.Bool("x")
        result = Or_(False, x)
        assert result.decl().kind() == z3.Z3_OP_OR


class TestNotCombinator:
    """Test suite for Not_ in contracts/compiler.py."""

    def test_handles_bools(self) -> None:
        """Verify that Not_ handles python booleans."""
        result = Not_(True)
        assert z3.is_false(result)

    def test_handles_z3_boolref(self) -> None:
        """Verify that Not_ handles z3.BoolRef."""
        x = z3.Bool("x")
        result = Not_(x)
        assert result.decl().kind() == z3.Z3_OP_NOT


class TestImpliesCombinator:
    """Test suite for Implies_ in contracts/compiler.py."""

    def test_handles_bool_and_z3_boolref(self) -> None:
        """Verify that Implies_ handles python booleans and z3.BoolRef."""
        x = z3.Bool("x")
        result = Implies_(True, x)
        assert result.decl().kind() == z3.Z3_OP_IMPLIES


class TestFormulaCache:
    """Test suite for _FormulaCache in contracts/compiler.py."""

    def test_get_put_clear(self) -> None:
        """Verify get, put, and clear operations."""
        cache = _FormulaCache()
        key = (1, 2)
        val = z3.BoolVal(True)
        cache.put(key, val)
        assert cache.get(key) is not None
        cache.clear()
        assert cache.get(key) is None

    def test_eviction_when_full(self) -> None:
        """Verify eviction occurs when max_size is reached."""
        cache = _FormulaCache(max_size=2)
        cache.put((1, 1), z3.BoolVal(True))
        cache.put((2, 2), z3.BoolVal(True))
        cache.put((3, 3), z3.BoolVal(True))
        assert len(cache._cache) <= 2


class TestContractCompiler:
    """Test suite for ContractCompiler in contracts/compiler.py."""

    def setup_method(self) -> None:
        _formula_cache.clear()

    def test_compile_predicate_string(self) -> None:
        """Verify string predicate compilation."""
        symbols = {"x": z3.Int("x")}
        result = ContractCompiler.compile_predicate("x > 0", symbols)
        assert isinstance(result, z3.BoolRef)

    def test_compile_predicate_callable(self) -> None:
        """Verify callable predicate compilation."""
        symbols = {"x": z3.Int("x")}

        def pred(x: z3.ArithRef) -> z3.BoolRef:
            return x > 0

        result = ContractCompiler.compile_predicate(pred, symbols)
        assert isinstance(result, z3.BoolRef)

    def test_compile_predicate_invalid_type(self) -> None:
        """Verify TypeError on invalid predicate type."""
        symbols = {"x": z3.Int("x")}
        with pytest.raises(TypeError, match="must be a callable or string"):
            ContractCompiler.compile_predicate(123, symbols)  # type: ignore[arg-type]

    def test_compile_expression(self) -> None:
        """Verify backward-compatible string compilation."""
        symbols = {"y": z3.Int("y")}
        result = ContractCompiler.compile_expression("y == 1", symbols)
        assert isinstance(result, z3.BoolRef)

    def test_trace_callable_valid(self) -> None:
        """Verify tracing a valid boolean predicate."""
        symbols = {"z": z3.Int("z")}
        result = ContractCompiler._trace_callable(lambda z: z == 0, symbols)  # type: ignore
        assert isinstance(result, z3.BoolRef)

    def test_trace_callable_caches_result(self) -> None:
        """Verify tracing caches the result."""
        symbols = {"z": z3.Int("z")}

        def pred(z: z3.ArithRef) -> z3.BoolRef:
            return z == 0

        ContractCompiler._trace_callable(pred, symbols)
        assert len(_formula_cache._cache) > 0

    def test_trace_callable_fallback_on_exception(self) -> None:
        """Verify tracing falls back to True on exception."""
        symbols = {"z": z3.Int("z")}

        def pred(z: z3.ArithRef) -> z3.BoolRef:
            raise ValueError("Tracing failed")

        result = ContractCompiler._trace_callable(pred, symbols)
        assert z3.is_true(result)

    def test_coerce_to_bool_ref(self) -> None:
        """Verify coercion logic for different types."""
        res_boolref = ContractCompiler._coerce_to_bool_ref(z3.BoolVal(False), "src")
        assert isinstance(res_boolref, z3.BoolRef)
        res_bool = ContractCompiler._coerce_to_bool_ref(True, "src")
        assert z3.is_true(res_bool)
        res_arith = ContractCompiler._coerce_to_bool_ref(z3.IntVal(1), "src")
        assert isinstance(res_arith, z3.BoolRef)
        res_unknown = ContractCompiler._coerce_to_bool_ref("unknown", "src")
        assert z3.is_true(res_unknown)
