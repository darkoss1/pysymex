from __future__ import annotations

from collections.abc import Callable

import pytest
import z3

from pysymex.contracts.compiler import (
    And_,
    Implies_,
    Not_,
    Or_,
    FormulaCache,
    ContractCompiler,
    formula_cache,
)
from pysymex.contracts.binding import old_symbol_name


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
        assert z3.eq(result, x)

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
        assert z3.eq(result, x)

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
    """Test suite for FormulaCache in contracts/compiler.py."""

    def test_get_put_clear(self) -> None:
        """Verify get, put, and clear operations."""
        cache = FormulaCache()
        key = (1, (2,))
        val = z3.BoolVal(True)
        cache.put(key, val)
        assert cache.get(key) is not None
        cache.clear()
        assert cache.get(key) is None

    def test_eviction_when_full(self) -> None:
        """Verify eviction occurs when max_size is reached."""
        cache = FormulaCache(max_size=2)
        cache.put((1, (1,)), z3.BoolVal(True))
        cache.put((2, (2,)), z3.BoolVal(True))
        cache.put((3, (3,)), z3.BoolVal(True))
        assert len(cache.cache) <= 2

    def test_eviction_is_lru(self) -> None:
        """A cache hit refreshes recency before the next eviction."""
        cache = FormulaCache(max_size=3)
        cache.put((1, ()), z3.BoolVal(True))
        cache.put((2, ()), z3.BoolVal(True))
        cache.put((3, ()), z3.BoolVal(True))

        assert cache.get((1, ())) is not None
        cache.put((4, ()), z3.BoolVal(True))

        assert (1, ()) in cache.cache
        assert (2, ()) not in cache.cache
        assert (3, ()) in cache.cache
        assert (4, ()) in cache.cache

    def test_rejects_non_positive_size(self) -> None:
        """LRU caches require a positive capacity."""
        with pytest.raises(ValueError, match="max_size must be at least 1"):
            FormulaCache(max_size=0)


class TestContractCompiler:
    """Test suite for ContractCompiler in contracts/compiler.py."""

    def setup_method(self) -> None:
        formula_cache.clear()

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
        """Verify string predicate compilation."""
        symbols = {"y": z3.Int("y")}
        result = ContractCompiler.compile_expression("y == 1", symbols)
        assert isinstance(result, z3.BoolRef)

    def test_string_old_uses_bound_scalar_snapshot(self) -> None:
        """String ``old(x)`` resolves to the entry snapshot symbol."""
        x = z3.Int("x")
        old_x = z3.Int("entry_x")

        result = ContractCompiler.compile_expression(
            "x >= old(x)",
            {"x": x, old_symbol_name("x"): old_x},
        )

        assert z3.eq(result, x >= old_x)

    def test_string_old_supports_shallow_attribute_snapshot(self) -> None:
        """String ``old(self.x)`` resolves to the entry attribute snapshot."""
        current_balance = z3.Int("current_balance")
        old_balance = z3.Int("old_balance")

        result = ContractCompiler.compile_expression(
            "self.balance >= old(self.balance)",
            {
                "self.balance": current_balance,
                old_symbol_name("self.balance"): old_balance,
            },
        )

        assert z3.eq(result, current_balance >= old_balance)

    def test_string_old_supports_length_snapshot(self) -> None:
        """String ``old(len(xs))`` resolves to the entry length snapshot."""
        result_len = z3.Int("result_len")
        old_len = z3.Int("old_len")

        result = ContractCompiler.compile_expression(
            "len(result()) == old(len(xs))",
            {
                "len___result__": result_len,
                old_symbol_name("len(xs)"): old_len,
            },
        )

        assert z3.eq(result, result_len == old_len)

    def test_string_old_requires_bound_scalar_snapshot(self) -> None:
        """Missing old bindings stay unsupported instead of becoming fresh vars."""
        with pytest.raises(ValueError, match="supported entry snapshot"):
            ContractCompiler.compile_expression("x >= old(x)", {"x": z3.Int("x")})

    def test_trace_callable_valid(self) -> None:
        """Verify tracing a valid boolean predicate."""
        symbols = {"z": z3.Int("z")}
        result = ContractCompiler.trace_callable(lambda z: z == 0, symbols)  # type: ignore
        assert isinstance(result, z3.BoolRef)

    def test_trace_callable_does_not_reuse_captured_state(self) -> None:
        """Callable clauses with distinct captured values keep distinct formulas."""
        symbols = {"z": z3.Int("z")}

        def limited(bound: int) -> Callable[[z3.ArithRef], z3.BoolRef]:
            def predicate(z: z3.ArithRef) -> z3.BoolRef:
                return z > bound

            return predicate

        first = ContractCompiler.trace_callable(limited(0), symbols)
        second = ContractCompiler.trace_callable(limited(10), symbols)

        assert z3.eq(first, symbols["z"] > 0)
        assert z3.eq(second, symbols["z"] > 10)

    def test_trace_callable_rejects_unbound_parameter(self) -> None:
        symbols = {"x": z3.Int("x")}

        def predicate(missing: z3.ArithRef) -> z3.BoolRef:
            return missing > 0

        with pytest.raises(ValueError, match="Unbound contract parameter: missing"):
            ContractCompiler.trace_callable(predicate, symbols)

    def test_trace_callable_rejects_partial_arithmetic(self) -> None:
        def contains_division(value: z3.ArithRef) -> z3.BoolRef:
            return value / 2 > 0

        def contains_modulo(value: z3.ArithRef) -> z3.BoolRef:
            return value % -2 == 1

        def contains_power(value: z3.ArithRef) -> z3.BoolRef:
            return value**2 > 0

        predicates: tuple[Callable[[z3.ArithRef], z3.BoolRef], ...] = (
            contains_division,
            contains_modulo,
            contains_power,
        )
        for predicate in predicates:
            with pytest.raises(ValueError, match="terms are unsupported"):
                ContractCompiler.trace_callable(predicate, {"value": z3.Int("value")})

    def test_trace_callable_rejects_real_arithmetic(self) -> None:
        def contains_real_term(value: z3.ArithRef) -> z3.BoolRef:
            return value > z3.RealVal("0.1")

        with pytest.raises(ValueError, match="real or floating-point terms are unsupported"):
            ContractCompiler.trace_callable(contains_real_term, {"value": z3.Real("value")})

    def test_trace_callable_rejects_parameterized_concrete_bool(self) -> None:
        def runtime_type_check(value: object) -> bool:
            return isinstance(value, int)

        with pytest.raises(ValueError, match="returning Python bool are unsupported"):
            ContractCompiler.trace_callable(runtime_type_check, {"value": z3.Int("value")})

    def test_trace_callable_reports_exception(self) -> None:
        """Verify tracing exceptions are explicit instead of weakening to True."""
        symbols = {"z": z3.Int("z")}

        def pred(z: z3.ArithRef) -> z3.BoolRef:
            raise ValueError("Tracing failed")

        with pytest.raises(ValueError, match="could not be symbolically traced"):
            ContractCompiler.trace_callable(pred, symbols)

    def test_coerce_to_bool_ref(self) -> None:
        """Verify coercion logic for different types."""
        res_boolref = ContractCompiler.coerce_to_bool_ref(z3.BoolVal(False), "src")
        assert isinstance(res_boolref, z3.BoolRef)
        res_bool = ContractCompiler.coerce_to_bool_ref(True, "src")
        assert z3.is_true(res_bool)
        res_arith = ContractCompiler.coerce_to_bool_ref(z3.IntVal(1), "src")
        assert isinstance(res_arith, z3.BoolRef)
        with pytest.raises(ValueError, match="unsupported result type"):
            ContractCompiler.coerce_to_bool_ref("unknown", "src")
