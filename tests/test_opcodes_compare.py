"""Tests for comparison opcode handlers."""

import pytest
import z3

from tests.helpers import (
    dispatch, from_const, make_state, make_symbolic_int, make_symbolic_str,
    prove, solve,
)
from pysymex.core.types import SymbolicValue, SymbolicString, SymbolicNone, Z3_TRUE, Z3_FALSE
from pysymex.analysis.detectors import IssueKind


class TestCompareOpEquals:
    def test_concrete_equal(self):
        state = make_state(stack=[from_const(5), from_const(5)])
        r = dispatch("COMPARE_OP", state, argval="==")
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_bool == z3.BoolVal(True))

    def test_concrete_not_equal(self):
        state = make_state(stack=[from_const(5), from_const(3)])
        r = dispatch("COMPARE_OP", state, argval="==")
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_bool == z3.BoolVal(False))

    def test_symbolic_eq(self):
        x = make_symbolic_int("x")
        y = make_symbolic_int("y")
        state = make_state(stack=[x, y])
        r = dispatch("COMPARE_OP", state, argval="==")
        top = r.new_states[0].stack[-1]
        assert isinstance(top, SymbolicValue)
        # When x==y, result should be true
        assert solve(z3.And(x.z3_int == y.z3_int, top.z3_bool))

    def test_symbolic_eq_with_constraint(self):
        x = make_symbolic_int("x")
        y = make_symbolic_int("y")
        state = make_state(stack=[x, y], constraints=[x.z3_int == y.z3_int])
        r = dispatch("COMPARE_OP", state, argval="==")
        assert len(r.new_states) >= 1

    def test_string_eq(self):
        a = SymbolicString.from_const("hello")
        b = SymbolicString.from_const("hello")
        state = make_state(stack=[a, b])
        r = dispatch("COMPARE_OP", state, argval="==")
        assert len(r.new_states) >= 1


class TestCompareOpNotEquals:
    def test_concrete_different(self):
        state = make_state(stack=[from_const(5), from_const(3)])
        r = dispatch("COMPARE_OP", state, argval="!=")
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_bool == z3.BoolVal(True))

    def test_concrete_same(self):
        state = make_state(stack=[from_const(5), from_const(5)])
        r = dispatch("COMPARE_OP", state, argval="!=")
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_bool == z3.BoolVal(False))

    def test_symbolic_ne(self):
        x = make_symbolic_int("x")
        y = make_symbolic_int("y")
        state = make_state(stack=[x, y])
        r = dispatch("COMPARE_OP", state, argval="!=")
        assert len(r.new_states) >= 1


class TestCompareOpLess:
    def test_concrete_true(self):
        state = make_state(stack=[from_const(3), from_const(5)])
        r = dispatch("COMPARE_OP", state, argval="<")
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_bool == z3.BoolVal(True))

    def test_concrete_false(self):
        state = make_state(stack=[from_const(5), from_const(3)])
        r = dispatch("COMPARE_OP", state, argval="<")
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_bool == z3.BoolVal(False))

    def test_concrete_equal_is_false(self):
        state = make_state(stack=[from_const(5), from_const(5)])
        r = dispatch("COMPARE_OP", state, argval="<")
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_bool == z3.BoolVal(False))

    def test_symbolic(self):
        x = make_symbolic_int("x")
        y = make_symbolic_int("y")
        state = make_state(stack=[x, y])
        r = dispatch("COMPARE_OP", state, argval="<")
        assert len(r.new_states) >= 1


class TestCompareOpLessEqual:
    def test_concrete_true(self):
        state = make_state(stack=[from_const(3), from_const(5)])
        r = dispatch("COMPARE_OP", state, argval="<=")
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_bool == z3.BoolVal(True))

    def test_concrete_equal(self):
        state = make_state(stack=[from_const(5), from_const(5)])
        r = dispatch("COMPARE_OP", state, argval="<=")
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_bool == z3.BoolVal(True))

    def test_concrete_false(self):
        state = make_state(stack=[from_const(7), from_const(5)])
        r = dispatch("COMPARE_OP", state, argval="<=")
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_bool == z3.BoolVal(False))


class TestCompareOpGreater:
    def test_concrete_true(self):
        state = make_state(stack=[from_const(5), from_const(3)])
        r = dispatch("COMPARE_OP", state, argval=">")
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_bool == z3.BoolVal(True))

    def test_concrete_false(self):
        state = make_state(stack=[from_const(3), from_const(5)])
        r = dispatch("COMPARE_OP", state, argval=">")
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_bool == z3.BoolVal(False))


class TestCompareOpGreaterEqual:
    def test_concrete_true(self):
        state = make_state(stack=[from_const(5), from_const(3)])
        r = dispatch("COMPARE_OP", state, argval=">=")
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_bool == z3.BoolVal(True))

    def test_concrete_equal(self):
        state = make_state(stack=[from_const(5), from_const(5)])
        r = dispatch("COMPARE_OP", state, argval=">=")
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_bool == z3.BoolVal(True))


class TestCompareOpBoolWrapped:
    def test_bool_wrapped_eq(self):
        """Python 3.12+ wraps compare ops as bool(==)."""
        state = make_state(stack=[from_const(5), from_const(5)])
        r = dispatch("COMPARE_OP", state, argval="bool(==)")
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_bool == z3.BoolVal(True))


class TestIsOp:
    def test_none_is_none(self):
        none1 = SymbolicNone()
        none2 = SymbolicNone()
        state = make_state(stack=[none1, none2])
        r = dispatch("IS_OP", state, argval=0)
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_bool == z3.BoolVal(True))

    def test_value_is_not_none(self):
        val = from_const(42)
        none_val = SymbolicNone()
        state = make_state(stack=[val, none_val])
        r = dispatch("IS_OP", state, argval=0)
        assert len(r.new_states) == 1

    def test_is_not_inverted(self):
        none1 = SymbolicNone()
        none2 = SymbolicNone()
        state = make_state(stack=[none1, none2])
        r = dispatch("IS_OP", state, argval=1)  # is not
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_bool == z3.BoolVal(False))

    def test_symbolic_is_none(self):
        x = make_symbolic_int("x")
        none_val = SymbolicNone()
        state = make_state(stack=[x, none_val])
        r = dispatch("IS_OP", state, argval=0)
        assert len(r.new_states) == 1


class TestContainsOp:
    @pytest.mark.xfail(reason="pre-existing: SymbolicString lacks contains() method")
    def test_string_in_string(self):
        haystack = SymbolicString.from_const("hello world")
        needle = SymbolicString.from_const("hello")
        state = make_state(stack=[needle, haystack])
        r = dispatch("CONTAINS_OP", state, argval=0)
        assert len(r.new_states) == 1
        top = r.new_states[0].stack[-1]
        assert isinstance(top, SymbolicValue)

    @pytest.mark.xfail(reason="pre-existing: SymbolicString lacks contains() method")
    def test_not_in(self):
        haystack = SymbolicString.from_const("hello world")
        needle = SymbolicString.from_const("hello")
        state = make_state(stack=[needle, haystack])
        r = dispatch("CONTAINS_OP", state, argval=1)  # not in
        assert len(r.new_states) == 1

    @pytest.mark.xfail(reason="pre-existing: SymbolicString lacks contains() method")
    def test_symbolic_contains(self):
        haystack = make_symbolic_str("s1")
        needle = make_symbolic_str("s2")
        state = make_state(stack=[needle, haystack])
        r = dispatch("CONTAINS_OP", state, argval=0)
        assert len(r.new_states) == 1

    def test_fallback_fresh_bool(self):
        val = from_const(42)
        container = from_const(100)
        state = make_state(stack=[val, container])
        r = dispatch("CONTAINS_OP", state, argval=0)
        assert len(r.new_states) == 1


class TestCompareResultType:
    def test_result_is_bool_typed(self):
        state = make_state(stack=[from_const(1), from_const(2)])
        r = dispatch("COMPARE_OP", state, argval="<")
        top = r.new_states[0].stack[-1]
        assert prove(top.is_bool == z3.BoolVal(True))
        assert prove(top.is_int == z3.BoolVal(False))

    def test_is_op_result_is_bool(self):
        none1 = SymbolicNone()
        none2 = SymbolicNone()
        state = make_state(stack=[none1, none2])
        r = dispatch("IS_OP", state, argval=0)
        top = r.new_states[0].stack[-1]
        assert prove(top.is_bool == z3.BoolVal(True))
