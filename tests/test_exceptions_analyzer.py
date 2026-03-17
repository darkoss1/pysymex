"""Tests for pysymex.core.exceptions_analyzer — exception analysis utilities.

Covers: ExceptionAnalyzer (add_potential_exception, get_potential_exceptions,
get_exceptions_of_type, verify_raises_contract, check_unhandled_exceptions,
analyze_division, analyze_index_access, analyze_key_access,
analyze_attribute_access, analyze_assertion),
create_exception_from_opcode, propagate_exception, merge_exception_states,
is_builtin_exception, get_exception_hierarchy,
check_precondition_violation, check_postcondition_violation,
check_invariant_violation, BUILTIN_EXCEPTIONS.
"""

from __future__ import annotations

import z3
import pytest

from pysymex.core.exceptions_analyzer import (
    BUILTIN_EXCEPTIONS,
    ExceptionAnalyzer,
    check_invariant_violation,
    check_postcondition_violation,
    check_precondition_violation,
    create_exception_from_opcode,
    get_exception_hierarchy,
    is_builtin_exception,
    merge_exception_states,
    propagate_exception,
)
from pysymex.core.exceptions_types import (
    ExceptionHandler,
    ExceptionPath,
    ExceptionState,
    RaisesContract,
    SymbolicException,
    TryBlock,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_analyzer() -> ExceptionAnalyzer:
    return ExceptionAnalyzer()


def _concrete_exc(
    exc_type: type[BaseException] = ValueError,
    msg: str = "test error",
    pc: int = 0,
) -> SymbolicException:
    return SymbolicException.concrete(exc_type, msg, raised_at=pc)


def _symbolic_exc(
    exc_type: type[BaseException] = ValueError,
    pc: int = 0,
) -> SymbolicException:
    cond = z3.Bool(f"cond_{pc}")
    return SymbolicException.symbolic(f"exc_{pc}", exc_type, cond, pc)


# ---------------------------------------------------------------------------
# ExceptionAnalyzer — add / get
# ---------------------------------------------------------------------------

class TestAnalyzerAddGet:

    def test_add_and_get_single(self):
        a = _make_analyzer()
        exc = _concrete_exc()
        a.add_potential_exception(exc)
        assert len(a.get_potential_exceptions()) == 1

    def test_add_multiple(self):
        a = _make_analyzer()
        a.add_potential_exception(_concrete_exc(ValueError))
        a.add_potential_exception(_concrete_exc(TypeError))
        assert len(a.get_potential_exceptions()) == 2

    def test_add_with_path_condition(self):
        a = _make_analyzer()
        exc = _concrete_exc()
        pc = z3.Bool("path_cond")
        a.add_potential_exception(exc, path_condition=pc)
        stored = a.get_potential_exceptions()[0]
        # condition should be ANDed with path_condition
        assert stored.condition is not None

    def test_get_empty(self):
        a = _make_analyzer()
        assert a.get_potential_exceptions() == []


# ---------------------------------------------------------------------------
# get_exceptions_of_type
# ---------------------------------------------------------------------------

class TestGetExceptionsOfType:

    def test_exact_type_match(self):
        a = _make_analyzer()
        a.add_potential_exception(_concrete_exc(ValueError))
        a.add_potential_exception(_concrete_exc(TypeError))
        results = a.get_exceptions_of_type(ValueError)
        assert len(results) == 1
        assert results[0].type_name == "ValueError"

    def test_subclass_match(self):
        a = _make_analyzer()
        a.add_potential_exception(_concrete_exc(ZeroDivisionError))
        results = a.get_exceptions_of_type(ArithmeticError)
        assert len(results) == 1

    def test_no_match(self):
        a = _make_analyzer()
        a.add_potential_exception(_concrete_exc(ValueError))
        results = a.get_exceptions_of_type(TypeError)
        assert len(results) == 0

    def test_string_type_name_match(self):
        a = _make_analyzer()
        exc = SymbolicException.symbolic("e", "CustomError", z3.BoolVal(True), 0)
        a.add_potential_exception(exc)
        # When exc_type is a string, it matches by type_name
        results = a.get_exceptions_of_type(ValueError)
        assert len(results) == 0  # "CustomError" != "ValueError"


# ---------------------------------------------------------------------------
# verify_raises_contract
# ---------------------------------------------------------------------------

class TestVerifyRaisesContract:

    def test_satisfied_no_context(self):
        a = _make_analyzer()
        a.add_potential_exception(_concrete_exc(ValueError, "bad value"))
        contract = RaisesContract(exc_type=ValueError)
        satisfied, msg = a.verify_raises_contract(contract)
        assert satisfied is True
        assert msg is None

    def test_not_satisfied_no_match(self):
        a = _make_analyzer()
        a.add_potential_exception(_concrete_exc(TypeError))
        contract = RaisesContract(exc_type=ValueError)
        satisfied, msg = a.verify_raises_contract(contract)
        assert satisfied is False
        assert msg is not None

    def test_satisfied_with_context_constraints(self):
        a = _make_analyzer()
        x = z3.Int("x")
        exc = SymbolicException.symbolic("e", ValueError, x < 0, 10)
        a.add_potential_exception(exc)
        contract = RaisesContract(exc_type=ValueError)
        satisfied, msg = a.verify_raises_contract(
            contract, context_constraints=[x == -5]
        )
        assert satisfied is True

    def test_not_feasible_with_context_constraints(self):
        a = _make_analyzer()
        x = z3.Int("x")
        exc = SymbolicException.symbolic("e", ValueError, x < 0, 10)
        a.add_potential_exception(exc)
        contract = RaisesContract(exc_type=ValueError)
        satisfied, msg = a.verify_raises_contract(
            contract, context_constraints=[x > 100]
        )
        assert satisfied is False

    def test_unconditional_exception_always_feasible(self):
        a = _make_analyzer()
        exc = _concrete_exc(ValueError)  # condition is BoolVal(True)
        a.add_potential_exception(exc)
        contract = RaisesContract(exc_type=ValueError)
        x = z3.Int("x")
        satisfied, _ = a.verify_raises_contract(
            contract, context_constraints=[x > 0]
        )
        assert satisfied is True


# ---------------------------------------------------------------------------
# check_unhandled_exceptions
# ---------------------------------------------------------------------------

class TestCheckUnhandled:

    def test_propagated_reported(self):
        a = _make_analyzer()
        exc = _concrete_exc()
        path = ExceptionPath(exception=exc, propagated=True)
        state = ExceptionState(exception_paths=[path])
        unhandled = a.check_unhandled_exceptions(state)
        assert len(unhandled) == 1

    def test_caught_not_reported(self):
        a = _make_analyzer()
        exc = _concrete_exc()
        handler = ExceptionHandler(exc_types=(ValueError,), target_pc=100)
        path = ExceptionPath(exception=exc, propagated=False, caught_by=handler)
        state = ExceptionState(exception_paths=[path])
        unhandled = a.check_unhandled_exceptions(state)
        assert len(unhandled) == 0

    def test_empty_state(self):
        a = _make_analyzer()
        state = ExceptionState()
        assert a.check_unhandled_exceptions(state) == []


# ---------------------------------------------------------------------------
# analyze_division
# ---------------------------------------------------------------------------

class TestAnalyzeDivision:

    def test_concrete_zero(self):
        a = _make_analyzer()
        exc = a.analyze_division(0, pc=10)
        assert exc is not None
        assert exc.type_name == "ZeroDivisionError"

    def test_concrete_nonzero(self):
        a = _make_analyzer()
        assert a.analyze_division(5, pc=10) is None

    def test_concrete_float_zero(self):
        a = _make_analyzer()
        exc = a.analyze_division(0.0, pc=10)
        assert exc is not None

    def test_symbolic_divisor(self):
        a = _make_analyzer()

        class FakeDivisor:
            def to_z3(self):
                return z3.Int("d")

        exc = a.analyze_division(FakeDivisor(), pc=20)
        assert exc is not None
        assert exc.condition is not None

    def test_unknown_divisor(self):
        a = _make_analyzer()
        exc = a.analyze_division("not_numeric", pc=30)
        assert exc is not None  # Returns symbolic exception with fresh bool


# ---------------------------------------------------------------------------
# analyze_index_access
# ---------------------------------------------------------------------------

class TestAnalyzeIndexAccess:

    def test_concrete_in_bounds(self):
        a = _make_analyzer()

        class FakeList:
            length = 5

        assert a.analyze_index_access(FakeList(), 2, pc=10) is None

    def test_concrete_out_of_bounds(self):
        a = _make_analyzer()

        class FakeList:
            length = 5

        exc = a.analyze_index_access(FakeList(), 10, pc=10)
        assert exc is not None
        assert exc.type_name == "IndexError"

    def test_concrete_negative_out_of_bounds(self):
        a = _make_analyzer()

        class FakeList:
            length = 3

        exc = a.analyze_index_access(FakeList(), -5, pc=10)
        assert exc is not None

    def test_symbolic_length(self):
        a = _make_analyzer()

        class FakeLen:
            def to_z3(self):
                return z3.Int("length")

        class FakeList:
            length = FakeLen()

        exc = a.analyze_index_access(FakeList(), 2, pc=10)
        assert exc is not None
        assert exc.condition is not None

    def test_no_length_attribute(self):
        a = _make_analyzer()
        assert a.analyze_index_access("not_a_container", 0, pc=10) is None


# ---------------------------------------------------------------------------
# analyze_key_access
# ---------------------------------------------------------------------------

class TestAnalyzeKeyAccess:

    def test_key_missing_concrete(self):
        a = _make_analyzer()

        class FakeDict:
            def contains(self): pass
            def contains_key(self, k):
                return False

        exc = a.analyze_key_access(FakeDict(), "missing", pc=10)
        assert exc is not None
        assert exc.type_name == "KeyError"

    def test_key_present_concrete(self):
        a = _make_analyzer()

        class FakeDict:
            def contains(self): pass
            def contains_key(self, k):
                return True

        assert a.analyze_key_access(FakeDict(), "present", pc=10) is None

    def test_generic_container(self):
        a = _make_analyzer()
        # No contains method -> returns symbolic exception
        exc = a.analyze_key_access(object(), "key", pc=10)
        assert exc is not None


# ---------------------------------------------------------------------------
# analyze_attribute_access
# ---------------------------------------------------------------------------

class TestAnalyzeAttributeAccess:

    def test_none_object(self):
        a = _make_analyzer()
        exc = a.analyze_attribute_access(None, "foo", pc=10)
        assert exc is not None
        assert exc.type_name == "AttributeError"
        assert "NoneType" in exc.message

    def test_has_attribute_true(self):
        a = _make_analyzer()

        class FakeObj:
            def has_attribute(self, name):
                return True

        assert a.analyze_attribute_access(FakeObj(), "x", pc=10) is None

    def test_has_attribute_false(self):
        a = _make_analyzer()

        class FakeObj:
            def has_attribute(self, name):
                return False

        exc = a.analyze_attribute_access(FakeObj(), "x", pc=10)
        assert exc is not None
        assert exc.type_name == "AttributeError"

    def test_no_has_attribute_method(self):
        a = _make_analyzer()
        assert a.analyze_attribute_access(42, "x", pc=10) is None


# ---------------------------------------------------------------------------
# analyze_assertion
# ---------------------------------------------------------------------------

class TestAnalyzeAssertion:

    def test_concrete_false(self):
        a = _make_analyzer()
        exc = a.analyze_assertion(False, "must be true", pc=10)
        assert exc is not None
        assert exc.type_name == "AssertionError"
        assert exc.message == "must be true"

    def test_concrete_true(self):
        a = _make_analyzer()
        assert a.analyze_assertion(True, None, pc=10) is None

    def test_symbolic_condition(self):
        a = _make_analyzer()

        class FakeCond:
            def could_be_falsy(self):
                return z3.Bool("falsy")

        exc = a.analyze_assertion(FakeCond(), None, pc=10)
        assert exc is not None
        assert exc.condition is not None

    def test_unknown_condition(self):
        a = _make_analyzer()
        exc = a.analyze_assertion("maybe", None, pc=10)
        assert exc is not None  # Returns symbolic with fresh bool


# ---------------------------------------------------------------------------
# create_exception_from_opcode
# ---------------------------------------------------------------------------

class TestCreateExceptionFromOpcode:

    def test_basic_creation(self):
        exc = create_exception_from_opcode(ValueError, ("bad",), pc=42)
        assert exc.type_name == "ValueError"
        assert exc.raised_at == 42
        assert exc.message == "bad"

    def test_no_args(self):
        exc = create_exception_from_opcode(RuntimeError, (), pc=0)
        assert exc.type_name == "RuntimeError"

    def test_multiple_args(self):
        exc = create_exception_from_opcode(TypeError, ("a", "b"), pc=5)
        assert exc.args == ("a", "b")


# ---------------------------------------------------------------------------
# propagate_exception
# ---------------------------------------------------------------------------

class TestPropagateException:

    def test_caught_by_handler(self):
        handler = ExceptionHandler(exc_types=(ValueError,), target_pc=100)
        block = TryBlock(try_start=0, try_end=50, handlers=[handler])
        state = ExceptionState(try_stack=[block])
        exc = _concrete_exc(ValueError)
        handled, target = propagate_exception(state, exc)
        assert handled is True
        assert target == 100

    def test_not_caught(self):
        handler = ExceptionHandler(exc_types=(TypeError,), target_pc=100)
        block = TryBlock(try_start=0, try_end=50, handlers=[handler])
        state = ExceptionState(try_stack=[block])
        exc = _concrete_exc(ValueError)
        handled, target = propagate_exception(state, exc)
        assert handled is False
        assert target is None

    def test_empty_try_stack(self):
        state = ExceptionState()
        exc = _concrete_exc()
        handled, target = propagate_exception(state, exc)
        assert handled is False
        assert target is None

    def test_bare_except_catches_all(self):
        handler = ExceptionHandler(exc_types=None, target_pc=200)
        block = TryBlock(try_start=0, try_end=50, handlers=[handler])
        state = ExceptionState(try_stack=[block])
        exc = _concrete_exc(RuntimeError)
        handled, target = propagate_exception(state, exc)
        assert handled is True
        assert target == 200


# ---------------------------------------------------------------------------
# merge_exception_states
# ---------------------------------------------------------------------------

class TestMergeExceptionStates:

    def test_empty_list(self):
        result = merge_exception_states([])
        assert isinstance(result, ExceptionState)
        assert result.try_stack == []

    def test_single_state_cloned(self):
        s = ExceptionState()
        s.exception_paths.append(
            ExceptionPath(exception=_concrete_exc(), propagated=True)
        )
        result = merge_exception_states([s])
        assert len(result.exception_paths) == 1
        assert result is not s

    def test_merge_two_states_paths(self):
        s1 = ExceptionState()
        s1.exception_paths.append(
            ExceptionPath(exception=_concrete_exc(ValueError, pc=1), propagated=True)
        )
        s2 = ExceptionState()
        s2.exception_paths.append(
            ExceptionPath(exception=_concrete_exc(TypeError, pc=2), propagated=True)
        )
        result = merge_exception_states([s1, s2])
        assert len(result.exception_paths) == 2

    def test_merge_dedup_same_type_and_pc(self):
        exc = _concrete_exc(ValueError, pc=10)
        s1 = ExceptionState()
        s1.exception_paths.append(ExceptionPath(exception=exc, propagated=True))
        s2 = ExceptionState()
        s2.exception_paths.append(ExceptionPath(exception=exc, propagated=True))
        result = merge_exception_states([s1, s2])
        # Same (type_name, raised_at) should be deduped
        assert len(result.exception_paths) == 1

    def test_merge_try_stacks(self):
        block = TryBlock(try_start=0, try_end=50)
        s1 = ExceptionState(try_stack=[block])
        s2 = ExceptionState(try_stack=[block])
        result = merge_exception_states([s1, s2])
        assert len(result.try_stack) == 1

    def test_merge_current_exception(self):
        exc = _concrete_exc()
        s1 = ExceptionState(current_exception=exc)
        s2 = ExceptionState()
        result = merge_exception_states([s1, s2])
        assert result.current_exception is exc


# ---------------------------------------------------------------------------
# is_builtin_exception
# ---------------------------------------------------------------------------

class TestIsBuiltinException:

    def test_value_error(self):
        assert is_builtin_exception(ValueError) is True

    def test_type_error(self):
        assert is_builtin_exception(TypeError) is True

    def test_base_exception(self):
        assert is_builtin_exception(BaseException) is True

    def test_zero_division(self):
        assert is_builtin_exception(ZeroDivisionError) is True

    def test_keyboard_interrupt(self):
        assert is_builtin_exception(KeyboardInterrupt) is True

    def test_custom_exception(self):
        class MyError(Exception):
            pass

        assert is_builtin_exception(MyError) is False


# ---------------------------------------------------------------------------
# get_exception_hierarchy
# ---------------------------------------------------------------------------

class TestGetExceptionHierarchy:

    def test_value_error(self):
        h = get_exception_hierarchy(ValueError)
        assert ValueError in h
        assert Exception in h
        assert BaseException in h

    def test_zero_division_error(self):
        h = get_exception_hierarchy(ZeroDivisionError)
        assert ZeroDivisionError in h
        assert ArithmeticError in h
        assert Exception in h
        assert BaseException in h

    def test_base_exception(self):
        h = get_exception_hierarchy(BaseException)
        assert BaseException in h

    def test_custom_exception(self):
        class MyError(ValueError):
            pass

        h = get_exception_hierarchy(MyError)
        assert MyError in h
        assert ValueError in h
        assert Exception in h
        assert BaseException in h

    def test_returns_list(self):
        h = get_exception_hierarchy(RuntimeError)
        assert isinstance(h, list)

    def test_order_starts_with_type(self):
        h = get_exception_hierarchy(IndexError)
        assert h[0] is IndexError


# ---------------------------------------------------------------------------
# BUILTIN_EXCEPTIONS constant
# ---------------------------------------------------------------------------

class TestBuiltinExceptionsConstant:

    def test_is_frozenset(self):
        assert isinstance(BUILTIN_EXCEPTIONS, frozenset)

    def test_contains_common(self):
        for exc in (ValueError, TypeError, KeyError, IndexError, RuntimeError,
                    ZeroDivisionError, AttributeError, OSError):
            assert exc in BUILTIN_EXCEPTIONS

    def test_contains_base(self):
        assert BaseException in BUILTIN_EXCEPTIONS
        assert Exception in BUILTIN_EXCEPTIONS


# ---------------------------------------------------------------------------
# check_precondition_violation / postcondition / invariant
# ---------------------------------------------------------------------------

class TestContractViolations:

    def test_precondition(self):
        x = z3.Int("x")
        exc = check_precondition_violation(x > 0, "x must be positive", pc=10)
        assert exc is not None
        assert exc.type_name == "AssertionError"
        # condition should be Not(x > 0)
        s = z3.Solver()
        s.add(exc.condition)
        s.add(x == -1)
        assert s.check() == z3.sat

    def test_postcondition(self):
        x = z3.Int("x")
        exc = check_postcondition_violation(x > 0, "result positive", pc=20)
        assert exc is not None
        assert exc.type_name == "AssertionError"

    def test_invariant(self):
        x = z3.Int("x")
        exc = check_invariant_violation(x == 0, "must be zero", pc=30)
        assert exc is not None
        assert exc.type_name == "AssertionError"

    def test_precondition_condition_is_negation(self):
        cond = z3.BoolVal(True)
        exc = check_precondition_violation(cond, "always true", pc=0)
        assert exc is not None
        # Not(True) should be UNSAT - the violation cannot occur
        s = z3.Solver()
        s.add(exc.condition)
        assert s.check() == z3.unsat
