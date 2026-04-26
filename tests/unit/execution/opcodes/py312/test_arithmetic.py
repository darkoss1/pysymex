from __future__ import annotations

import dis

from pysymex.analysis.detectors import IssueKind
from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicNone, SymbolicValue
from pysymex.execution.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.py312 import arithmetic


def _instr(
    opname: str,
    argval: object = None,
    argrepr: str = "",
    offset: int = 0,
) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval, argrepr=argrepr, offset=offset)


def test_check_division_by_zero() -> None:
    """Test check_division_by_zero behavior."""
    state = VMState(pc=7)
    left = SymbolicValue.from_const(10)
    right = SymbolicValue.from_const(0)
    issues = arithmetic.check_division_by_zero(right, state, "/", left)
    assert len(issues) == 1
    assert issues[0].kind is IssueKind.DIVISION_BY_ZERO


def test_check_negative_shift() -> None:
    """Test check_negative_shift behavior."""
    state = VMState(pc=3)
    left = SymbolicValue.from_const(1)
    right = SymbolicValue.from_const(-1)
    issues = arithmetic.check_negative_shift(right, state, "<<", left)
    assert len(issues) == 1
    assert issues[0].kind is IssueKind.VALUE_ERROR


def test_handle_unary_negative() -> None:
    """Test handle_unary_negative behavior."""
    state = VMState(stack=[5], pc=0)
    result = arithmetic.handle_unary_negative(_instr("UNARY_NEGATIVE"), state, OpcodeDispatcher())
    assert result.new_states[0].peek() == -5


def test_handle_unary_not() -> None:
    """Test handle_unary_not behavior."""
    state = VMState(stack=[0], pc=0)
    result = arithmetic.handle_unary_not(_instr("UNARY_NOT"), state, OpcodeDispatcher())
    assert isinstance(result.new_states[0].peek(), SymbolicValue)


def test_handle_unary_invert() -> None:
    """Test handle_unary_invert behavior."""
    state = VMState(stack=[3], pc=0)
    result = arithmetic.handle_unary_invert(_instr("UNARY_INVERT"), state, OpcodeDispatcher())
    assert result.new_states[0].peek() == ~3


def test_handle_binary_op() -> None:
    """Test handle_binary_op behavior."""
    state = VMState(stack=[5, 6], pc=0)
    result = arithmetic.handle_binary_op(
        _instr("BINARY_OP", argrepr="+"), state, OpcodeDispatcher()
    )
    assert result.terminal is False
    assert isinstance(result.new_states[0].peek(), SymbolicValue)


def test_handle_load_attr() -> None:
    """Test handle_load_attr behavior."""
    state = VMState(stack=[SymbolicNone()], pc=0)
    result = arithmetic.handle_load_attr(_instr("LOAD_ATTR", "x"), state, OpcodeDispatcher())
    assert result.terminal is False
    assert result.new_states[0].pc == 1
