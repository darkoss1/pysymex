from __future__ import annotations

import dis

import pysymex._internal.execution.opcodes.py312.arithmetic as arithmetic
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.opcodes.common.numeric.guards import (
    check_negative_shift,
    division_by_zero_possible,
)


def _instr(
    opname: str,
    argval: object = None,
    argrepr: str = "",
    offset: int = 0,
) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval, argrepr=argrepr, offset=offset)


def test_division_by_zero_possible() -> None:
    """Test division_by_zero_possible behavior."""
    state = VMState(pc=7)
    left = SymbolicValue.from_const(10)
    right = SymbolicValue.from_const(0)
    has_zero = division_by_zero_possible(right, state, "/", left)
    assert has_zero is True


def test_check_negative_shift() -> None:
    """Test check_negative_shift behavior."""
    state = VMState(pc=3)
    left = SymbolicValue.from_const(1)
    right = SymbolicValue.from_const(-1)
    has_negative_shift = check_negative_shift(right, state, "<<", left)
    assert has_negative_shift is True


def test_handle_py312_unary_positive() -> None:
    """Test handle_py312_unary_positive behavior."""
    state = VMState(stack=[5], pc=0)
    result = arithmetic.handle_py312_unary_positive(
        _instr("UNARY_POSITIVE"), state, OpcodeDispatcher()
    )
    assert result.terminal is False
    assert result.new_states[0].peek() == 5


def test_handle_unary_positive_reports_concrete_string_type_error() -> None:
    """Unary plus on str follows CPython's definite TypeError path."""
    state = VMState(stack=["text"], pc=0)
    result = arithmetic.handle_py312_unary_positive(
        _instr("UNARY_POSITIVE"), state, OpcodeDispatcher()
    )
    assert result.terminal is True
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]


def test_handle_py312_unary_negative() -> None:
    """Test handle_py312_unary_negative behavior."""
    state = VMState(stack=[5], pc=0)
    result = arithmetic.handle_py312_unary_negative(
        _instr("UNARY_NEGATIVE"), state, OpcodeDispatcher()
    )
    assert result.new_states[0].peek() == -5


def test_handle_py312_unary_not() -> None:
    """Test handle_py312_unary_not behavior."""
    state = VMState(stack=[0], pc=0)
    result = arithmetic.handle_py312_unary_not(_instr("UNARY_NOT"), state, OpcodeDispatcher())
    assert isinstance(result.new_states[0].peek(), SymbolicValue)


def test_handle_py312_unary_invert() -> None:
    """Test handle_py312_unary_invert behavior."""
    state = VMState(stack=[3], pc=0)
    result = arithmetic.handle_py312_unary_invert(_instr("UNARY_INVERT"), state, OpcodeDispatcher())
    assert result.new_states[0].peek() == ~3


def test_handle_py312_binary_op() -> None:
    """Test handle_py312_binary_op behavior."""
    state = VMState(stack=[5, 6], pc=0)
    result = arithmetic.handle_py312_binary_op(
        _instr("BINARY_OP", argrepr="+"), state, OpcodeDispatcher()
    )
    assert result.terminal is False
    assert isinstance(result.new_states[0].peek(), SymbolicValue)


def test_handle_load_attr_reports_none_receiver() -> None:
    """LOAD_ATTR on None reports a feasible null dereference."""
    state = VMState(stack=[SymbolicNone()], pc=0)
    result = arithmetic.handle_py312_load_attr(_instr("LOAD_ATTR", "x"), state, OpcodeDispatcher())
    assert result.terminal is True
    assert [issue.kind for issue in result.issues] == [IssueKind.NULL_DEREFERENCE]
