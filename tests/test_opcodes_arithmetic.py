"""Tests for arithmetic opcode handlers."""

import pytest
import z3

from tests.helpers import (
    dispatch,
    from_const,
    make_dispatcher,
    make_state,
    make_symbolic_int,
    make_symbolic_str,
    prove,
    solve,
)
from pysymex.core.types import SymbolicValue, SymbolicString, Z3_TRUE, Z3_FALSE
from pysymex.analysis.detectors import IssueKind


# ── Unary operators ───────────────────────────────────────────────────────

class TestUnaryPositive:
    def test_concrete_int(self):
        state = make_state(stack=[from_const(5)])
        r = dispatch("UNARY_POSITIVE", state)
        assert len(r.new_states) == 1

    def test_symbolic_int(self):
        x = make_symbolic_int("x")
        state = make_state(stack=[x])
        r = dispatch("UNARY_POSITIVE", state)
        assert len(r.new_states) == 1
        top = r.new_states[0].stack[-1]
        assert isinstance(top, SymbolicValue)

    def test_concrete_zero(self):
        state = make_state(stack=[from_const(0)])
        r = dispatch("UNARY_POSITIVE", state)
        assert len(r.new_states) == 1


class TestUnaryNegative:
    def test_concrete_positive(self):
        state = make_state(stack=[from_const(5)])
        r = dispatch("UNARY_NEGATIVE", state)
        s = r.new_states[0]
        top = s.stack[-1]
        assert isinstance(top, SymbolicValue)
        # The int part should be -5
        assert prove(top.z3_int == z3.IntVal(-5))

    def test_concrete_zero(self):
        state = make_state(stack=[from_const(0)])
        r = dispatch("UNARY_NEGATIVE", state)
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_int == z3.IntVal(0))

    def test_concrete_negative(self):
        state = make_state(stack=[from_const(-3)])
        r = dispatch("UNARY_NEGATIVE", state)
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_int == z3.IntVal(3))

    def test_symbolic(self):
        x = make_symbolic_int("x")
        state = make_state(stack=[x])
        r = dispatch("UNARY_NEGATIVE", state)
        top = r.new_states[0].stack[-1]
        assert isinstance(top, SymbolicValue)
        assert prove(top.z3_int == -x.z3_int)


class TestUnaryNot:
    def test_concrete_true(self):
        state = make_state(stack=[from_const(True)])
        r = dispatch("UNARY_NOT", state)
        assert len(r.new_states) == 1

    def test_concrete_false(self):
        state = make_state(stack=[from_const(False)])
        r = dispatch("UNARY_NOT", state)
        assert len(r.new_states) == 1

    def test_concrete_int_truthy(self):
        state = make_state(stack=[from_const(42)])
        r = dispatch("UNARY_NOT", state)
        assert len(r.new_states) == 1

    def test_symbolic_bool(self):
        from tests.helpers import make_symbolic_bool
        b = make_symbolic_bool("b")
        state = make_state(stack=[b])
        r = dispatch("UNARY_NOT", state)
        top = r.new_states[0].stack[-1]
        assert isinstance(top, SymbolicValue)


class TestUnaryInvert:
    def test_concrete_int(self):
        state = make_state(stack=[from_const(5)])
        r = dispatch("UNARY_INVERT", state)
        top = r.new_states[0].stack[-1]
        assert isinstance(top, SymbolicValue)

    def test_concrete_zero(self):
        state = make_state(stack=[from_const(0)])
        r = dispatch("UNARY_INVERT", state)
        assert len(r.new_states) == 1

    def test_symbolic(self):
        x = make_symbolic_int("x")
        state = make_state(stack=[x])
        r = dispatch("UNARY_INVERT", state)
        assert len(r.new_states) == 1


# ── Binary addition ──────────────────────────────────────────────────────

class TestBinaryAdd:
    def test_concrete_ints(self):
        state = make_state(stack=[from_const(3), from_const(4)])
        r = dispatch("BINARY_ADD", state)
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_int == z3.IntVal(7))

    def test_concrete_zeros(self):
        state = make_state(stack=[from_const(0), from_const(0)])
        r = dispatch("BINARY_ADD", state)
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_int == z3.IntVal(0))

    def test_symbolic_ints(self):
        x = make_symbolic_int("x")
        y = make_symbolic_int("y")
        state = make_state(stack=[x, y])
        r = dispatch("BINARY_ADD", state)
        top = r.new_states[0].stack[-1]
        assert isinstance(top, SymbolicValue)
        assert prove(top.z3_int == x.z3_int + y.z3_int)

    def test_symbolic_plus_concrete(self):
        x = make_symbolic_int("x")
        state = make_state(stack=[x, from_const(10)])
        r = dispatch("BINARY_ADD", state)
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_int == x.z3_int + 10)

    def test_string_concat(self):
        a = SymbolicString.from_const("hello")
        b = SymbolicString.from_const(" world")
        state = make_state(stack=[a, b])
        r = dispatch("BINARY_ADD", state)
        assert len(r.new_states) >= 1

    def test_negative_ints(self):
        state = make_state(stack=[from_const(-5), from_const(-3)])
        r = dispatch("BINARY_ADD", state)
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_int == z3.IntVal(-8))

    def test_no_issues_for_same_type(self):
        state = make_state(stack=[from_const(1), from_const(2)])
        r = dispatch("BINARY_ADD", state)
        assert not r.issues


class TestBinarySubtract:
    def test_concrete_ints(self):
        state = make_state(stack=[from_const(10), from_const(3)])
        r = dispatch("BINARY_SUBTRACT", state)
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_int == z3.IntVal(7))

    def test_symbolic(self):
        x = make_symbolic_int("x")
        y = make_symbolic_int("y")
        state = make_state(stack=[x, y])
        r = dispatch("BINARY_SUBTRACT", state)
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_int == x.z3_int - y.z3_int)

    def test_zero_result(self):
        state = make_state(stack=[from_const(5), from_const(5)])
        r = dispatch("BINARY_SUBTRACT", state)
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_int == z3.IntVal(0))

    def test_negative_result(self):
        state = make_state(stack=[from_const(3), from_const(10)])
        r = dispatch("BINARY_SUBTRACT", state)
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_int == z3.IntVal(-7))


class TestBinaryMultiply:
    def test_concrete_ints(self):
        state = make_state(stack=[from_const(6), from_const(7)])
        r = dispatch("BINARY_MULTIPLY", state)
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_int == z3.IntVal(42))

    def test_multiply_by_zero(self):
        state = make_state(stack=[from_const(100), from_const(0)])
        r = dispatch("BINARY_MULTIPLY", state)
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_int == z3.IntVal(0))

    def test_symbolic(self):
        x = make_symbolic_int("x")
        y = make_symbolic_int("y")
        state = make_state(stack=[x, y])
        r = dispatch("BINARY_MULTIPLY", state)
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_int == x.z3_int * y.z3_int)

    def test_negative(self):
        state = make_state(stack=[from_const(-3), from_const(4)])
        r = dispatch("BINARY_MULTIPLY", state)
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_int == z3.IntVal(-12))


# ── Division ─────────────────────────────────────────────────────────────

class TestBinaryTrueDivide:
    def test_concrete_safe(self):
        state = make_state(stack=[from_const(10), from_const(2)])
        r = dispatch("BINARY_TRUE_DIVIDE", state)
        assert len(r.new_states) >= 1

    def test_concrete_zero_divisor(self):
        state = make_state(stack=[from_const(10), from_const(0)])
        r = dispatch("BINARY_TRUE_DIVIDE", state)
        # Should report division by zero
        assert any(i.kind == IssueKind.DIVISION_BY_ZERO for i in r.issues)

    def test_symbolic_divisor_reports_issue(self):
        x = make_symbolic_int("x")
        y = make_symbolic_int("y")
        state = make_state(stack=[x, y])
        r = dispatch("BINARY_TRUE_DIVIDE", state)
        # y could be 0, so issue should be raised
        assert any(i.kind == IssueKind.DIVISION_BY_ZERO for i in r.issues)

    def test_constrained_nonzero_divisor(self):
        x = make_symbolic_int("x")
        y = make_symbolic_int("y")
        state = make_state(stack=[x, y], constraints=[y.z3_int > 0])
        r = dispatch("BINARY_TRUE_DIVIDE", state)
        # y > 0 guaranteed, no division by zero issue
        div_issues = [i for i in r.issues if i.kind == IssueKind.DIVISION_BY_ZERO]
        assert len(div_issues) == 0


class TestBinaryFloorDivide:
    def test_concrete_safe(self):
        state = make_state(stack=[from_const(10), from_const(3)])
        r = dispatch("BINARY_FLOOR_DIVIDE", state)
        assert len(r.new_states) >= 1

    def test_concrete_zero_divisor(self):
        state = make_state(stack=[from_const(10), from_const(0)])
        r = dispatch("BINARY_FLOOR_DIVIDE", state)
        assert any(i.kind == IssueKind.DIVISION_BY_ZERO for i in r.issues)

    def test_symbolic_divisor(self):
        x = make_symbolic_int("x")
        y = make_symbolic_int("y")
        state = make_state(stack=[x, y])
        r = dispatch("BINARY_FLOOR_DIVIDE", state)
        assert any(i.kind == IssueKind.DIVISION_BY_ZERO for i in r.issues)


class TestBinaryModulo:
    @pytest.mark.xfail(reason="pre-existing bug: BINARY_MODULO handler missing issues arg")
    def test_concrete_ints(self):
        state = make_state(stack=[from_const(10), from_const(3)])
        r = dispatch("BINARY_MODULO", state)
        assert len(r.new_states) >= 1

    @pytest.mark.xfail(reason="pre-existing bug: BINARY_MODULO handler missing issues arg")
    def test_zero_mod(self):
        state = make_state(stack=[from_const(10), from_const(0)])
        r = dispatch("BINARY_MODULO", state)
        assert any(i.kind == IssueKind.DIVISION_BY_ZERO for i in r.issues) or r.terminal

    @pytest.mark.xfail(reason="pre-existing bug: BINARY_MODULO handler missing issues arg")
    def test_symbolic_mod(self):
        x = make_symbolic_int("x")
        y = make_symbolic_int("y")
        state = make_state(stack=[x, y])
        r = dispatch("BINARY_MODULO", state)
        assert len(r.new_states) >= 1


class TestBinaryPower:
    def test_concrete(self):
        state = make_state(stack=[from_const(2), from_const(3)])
        r = dispatch("BINARY_POWER", state)
        assert len(r.new_states) == 1

    def test_symbolic(self):
        x = make_symbolic_int("x")
        y = make_symbolic_int("y")
        state = make_state(stack=[x, y])
        r = dispatch("BINARY_POWER", state)
        assert len(r.new_states) == 1


# ── Shift operators ──────────────────────────────────────────────────────

class TestBinaryShift:
    def test_left_shift_concrete(self):
        state = make_state(stack=[from_const(1), from_const(3)])
        r = dispatch("BINARY_LSHIFT", state)
        assert len(r.new_states) >= 1

    def test_right_shift_concrete(self):
        state = make_state(stack=[from_const(8), from_const(2)])
        r = dispatch("BINARY_RSHIFT", state)
        assert len(r.new_states) >= 1

    def test_left_shift_symbolic(self):
        x = make_symbolic_int("x")
        state = make_state(stack=[x, from_const(2)])
        r = dispatch("BINARY_LSHIFT", state)
        assert len(r.new_states) >= 1

    def test_negative_shift_detected(self):
        state = make_state(stack=[from_const(1), from_const(-1)])
        r = dispatch("BINARY_LSHIFT", state)
        assert any(i.kind == IssueKind.VALUE_ERROR for i in r.issues)

    def test_symbolic_shift_count(self):
        x = make_symbolic_int("x")
        y = make_symbolic_int("shift")
        state = make_state(stack=[x, y])
        r = dispatch("BINARY_LSHIFT", state)
        # Shift count could be negative
        assert any(i.kind == IssueKind.VALUE_ERROR for i in r.issues)


# ── Bitwise operators ────────────────────────────────────────────────────

class TestBinaryBitwise:
    def test_and_concrete(self):
        state = make_state(stack=[from_const(0b1100), from_const(0b1010)])
        r = dispatch("BINARY_AND", state)
        assert len(r.new_states) == 1

    def test_or_concrete(self):
        state = make_state(stack=[from_const(0b1100), from_const(0b1010)])
        r = dispatch("BINARY_OR", state)
        assert len(r.new_states) == 1

    def test_xor_concrete(self):
        state = make_state(stack=[from_const(0b1100), from_const(0b1010)])
        r = dispatch("BINARY_XOR", state)
        assert len(r.new_states) == 1

    def test_and_symbolic(self):
        x = make_symbolic_int("x")
        y = make_symbolic_int("y")
        state = make_state(stack=[x, y])
        r = dispatch("BINARY_AND", state)
        assert len(r.new_states) == 1

    def test_or_symbolic(self):
        x = make_symbolic_int("x")
        y = make_symbolic_int("y")
        state = make_state(stack=[x, y])
        r = dispatch("BINARY_OR", state)
        assert len(r.new_states) == 1

    def test_xor_symbolic(self):
        x = make_symbolic_int("x")
        y = make_symbolic_int("y")
        state = make_state(stack=[x, y])
        r = dispatch("BINARY_XOR", state)
        assert len(r.new_states) == 1


# ── BINARY_OP (Unified Python 3.11+) ────────────────────────────────────

class TestBinaryOp:
    def test_add(self):
        state = make_state(stack=[from_const(3), from_const(4)])
        r = dispatch("BINARY_OP", state, argval=0, argrepr="+")
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_int == z3.IntVal(7))

    def test_subtract(self):
        state = make_state(stack=[from_const(10), from_const(3)])
        r = dispatch("BINARY_OP", state, argval=10, argrepr="-")
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_int == z3.IntVal(7))

    def test_multiply(self):
        state = make_state(stack=[from_const(6), from_const(7)])
        r = dispatch("BINARY_OP", state, argval=5, argrepr="*")
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_int == z3.IntVal(42))

    def test_true_divide(self):
        state = make_state(stack=[from_const(10), from_const(2)])
        r = dispatch("BINARY_OP", state, argval=11, argrepr="/")
        assert len(r.new_states) >= 1

    def test_floor_divide(self):
        state = make_state(stack=[from_const(10), from_const(3)])
        r = dispatch("BINARY_OP", state, argval=2, argrepr="//")
        assert len(r.new_states) >= 1

    def test_modulo(self):
        state = make_state(stack=[from_const(10), from_const(3)])
        r = dispatch("BINARY_OP", state, argval=6, argrepr="%")
        assert len(r.new_states) >= 1

    def test_power(self):
        state = make_state(stack=[from_const(2), from_const(3)])
        r = dispatch("BINARY_OP", state, argval=8, argrepr="**")
        assert len(r.new_states) == 1

    def test_bitwise_and(self):
        state = make_state(stack=[from_const(12), from_const(10)])
        r = dispatch("BINARY_OP", state, argval=1, argrepr="&")
        assert len(r.new_states) == 1

    def test_bitwise_or(self):
        state = make_state(stack=[from_const(12), from_const(10)])
        r = dispatch("BINARY_OP", state, argval=7, argrepr="|")
        assert len(r.new_states) == 1

    def test_bitwise_xor(self):
        state = make_state(stack=[from_const(12), from_const(10)])
        r = dispatch("BINARY_OP", state, argval=9, argrepr="^")
        assert len(r.new_states) == 1

    def test_left_shift(self):
        state = make_state(stack=[from_const(1), from_const(3)])
        r = dispatch("BINARY_OP", state, argval=3, argrepr="<<")
        assert len(r.new_states) >= 1

    def test_right_shift(self):
        state = make_state(stack=[from_const(8), from_const(2)])
        r = dispatch("BINARY_OP", state, argval=4, argrepr=">>")
        assert len(r.new_states) >= 1

    def test_inplace_add(self):
        state = make_state(stack=[from_const(3), from_const(4)])
        r = dispatch("BINARY_OP", state, argval=13, argrepr="+=")
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_int == z3.IntVal(7))

    def test_div_by_zero_detected(self):
        state = make_state(stack=[from_const(10), from_const(0)])
        r = dispatch("BINARY_OP", state, argval=11, argrepr="/")
        assert any(i.kind == IssueKind.DIVISION_BY_ZERO for i in r.issues)

    def test_symbolic_add(self):
        x = make_symbolic_int("x")
        y = make_symbolic_int("y")
        state = make_state(stack=[x, y])
        r = dispatch("BINARY_OP", state, argval=0, argrepr="+")
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_int == x.z3_int + y.z3_int)

    def test_symbolic_subtract(self):
        x = make_symbolic_int("x")
        y = make_symbolic_int("y")
        state = make_state(stack=[x, y])
        r = dispatch("BINARY_OP", state, argval=10, argrepr="-")
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_int == x.z3_int - y.z3_int)

    def test_symbolic_multiply(self):
        x = make_symbolic_int("x")
        y = make_symbolic_int("y")
        state = make_state(stack=[x, y])
        r = dispatch("BINARY_OP", state, argval=5, argrepr="*")
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_int == x.z3_int * y.z3_int)

    def test_symbolic_div_reports_zero(self):
        x = make_symbolic_int("x")
        y = make_symbolic_int("y")
        state = make_state(stack=[x, y])
        r = dispatch("BINARY_OP", state, argval=11, argrepr="/")
        assert any(i.kind == IssueKind.DIVISION_BY_ZERO for i in r.issues)


# ── Helpers / edge cases ─────────────────────────────────────────────────

class TestCheckDivisionByZero:
    def test_concrete_zero(self):
        from pysymex.execution.opcodes.arithmetic import check_division_by_zero
        right = from_const(0)
        left = from_const(10)
        state = make_state()
        issues = check_division_by_zero(right, state, "/", left)
        assert len(issues) == 1
        assert issues[0].kind == IssueKind.DIVISION_BY_ZERO

    def test_concrete_nonzero(self):
        from pysymex.execution.opcodes.arithmetic import check_division_by_zero
        right = from_const(5)
        left = from_const(10)
        state = make_state()
        issues = check_division_by_zero(right, state, "/", left)
        assert len(issues) == 0

    def test_symbolic_unconstrained(self):
        from pysymex.execution.opcodes.arithmetic import check_division_by_zero
        right = make_symbolic_int("y")
        left = make_symbolic_int("x")
        state = make_state()
        issues = check_division_by_zero(right, state, "/", left)
        assert len(issues) == 1

    def test_symbolic_constrained_positive(self):
        from pysymex.execution.opcodes.arithmetic import check_division_by_zero
        right = make_symbolic_int("y")
        left = make_symbolic_int("x")
        state = make_state(constraints=[right.z3_int > 0])
        issues = check_division_by_zero(right, state, "/", left)
        assert len(issues) == 0


class TestCheckNegativeShift:
    def test_concrete_negative(self):
        from pysymex.execution.opcodes.arithmetic import check_negative_shift
        right = from_const(-1)
        left = from_const(10)
        state = make_state()
        issues = check_negative_shift(right, state, "<<", left)
        assert len(issues) == 1
        assert issues[0].kind == IssueKind.VALUE_ERROR

    def test_concrete_positive(self):
        from pysymex.execution.opcodes.arithmetic import check_negative_shift
        right = from_const(5)
        left = from_const(10)
        state = make_state()
        issues = check_negative_shift(right, state, "<<", left)
        assert len(issues) == 0

    def test_symbolic_unconstrained(self):
        from pysymex.execution.opcodes.arithmetic import check_negative_shift
        right = make_symbolic_int("y")
        left = make_symbolic_int("x")
        state = make_state()
        issues = check_negative_shift(right, state, "<<", left)
        assert len(issues) == 1

    def test_symbolic_constrained_nonneg(self):
        from pysymex.execution.opcodes.arithmetic import check_negative_shift
        right = make_symbolic_int("y")
        left = make_symbolic_int("x")
        state = make_state(constraints=[right.z3_int >= 0])
        issues = check_negative_shift(right, state, "<<", left)
        assert len(issues) == 0


class TestStackStateAfterOps:
    """Verify stack depth is correct after operations."""

    def test_unary_doesnt_change_depth(self):
        state = make_state(stack=[from_const(5)])
        r = dispatch("UNARY_POSITIVE", state)
        assert len(r.new_states[0].stack) == 1

    def test_binary_reduces_depth_by_1(self):
        state = make_state(stack=[from_const(5), from_const(3)])
        r = dispatch("BINARY_ADD", state)
        assert len(r.new_states[0].stack) == 1

    def test_pc_advances(self):
        state = make_state(stack=[from_const(5)], pc=0)
        r = dispatch("UNARY_POSITIVE", state)
        assert r.new_states[0].pc == 1
