from __future__ import annotations

import dis

from pysymex.analysis.detectors import IssueKind
from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicValue
from pysymex.execution.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.base import arithmetic


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


def test_handle_unary_positive() -> None:
    """Test handle_unary_positive behavior."""
    state = VMState(stack=[5], pc=0)
    result = arithmetic.handle_unary_positive(_instr("UNARY_POSITIVE"), state, OpcodeDispatcher())
    assert result.terminal is False
    assert result.new_states[0].peek() == 5


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


def test_handle_binary_add() -> None:
    """Test handle_binary_add behavior."""
    state = VMState(stack=[1, 2], pc=0)
    result = arithmetic.handle_binary_add(_instr("BINARY_ADD"), state, OpcodeDispatcher())
    assert isinstance(result.new_states[0].peek(), SymbolicValue)


def test_handle_binary_subtract() -> None:
    """Test handle_binary_subtract behavior."""
    state = VMState(stack=[7, 2], pc=0)
    result = arithmetic.handle_binary_subtract(_instr("BINARY_SUBTRACT"), state, OpcodeDispatcher())
    assert isinstance(result.new_states[0].peek(), SymbolicValue)


def test_handle_binary_multiply() -> None:
    """Test handle_binary_multiply behavior."""
    state = VMState(stack=[4, 3], pc=0)
    result = arithmetic.handle_binary_multiply(_instr("BINARY_MULTIPLY"), state, OpcodeDispatcher())
    assert isinstance(result.new_states[0].peek(), SymbolicValue)


def test_handle_binary_divide() -> None:
    """Test handle_binary_divide behavior."""
    state = VMState(stack=[10, 0], pc=0)
    result = arithmetic.handle_binary_divide(
        _instr("BINARY_TRUE_DIVIDE"),
        state,
        OpcodeDispatcher(),
    )
    assert result.terminal is True
    assert any(issue.kind is IssueKind.DIVISION_BY_ZERO for issue in result.issues)


def test_handle_binary_modulo() -> None:
    """Test handle_binary_modulo behavior."""
    state = VMState(stack=[7, 3], pc=0)
    result = arithmetic.handle_binary_modulo(_instr("BINARY_MODULO"), state, OpcodeDispatcher())
    assert isinstance(result.new_states[0].peek(), SymbolicValue)


def test_handle_binary_power() -> None:
    """Test handle_binary_power behavior."""
    state = VMState(stack=[SymbolicValue.from_const(2), SymbolicValue.from_const(3)], pc=0)
    result = arithmetic.handle_binary_power(_instr("BINARY_POWER"), state, OpcodeDispatcher())
    assert isinstance(result.new_states[0].peek(), SymbolicValue)


def test_handle_binary_shift() -> None:
    """Test handle_binary_shift behavior."""
    state = VMState(stack=[4, -1], pc=0)
    result = arithmetic.handle_binary_shift(_instr("BINARY_LSHIFT"), state, OpcodeDispatcher())
    assert isinstance(result.new_states[0].peek(), SymbolicValue)
    assert any(issue.kind is IssueKind.VALUE_ERROR for issue in result.issues)


def test_handle_binary_and() -> None:
    """Test handle_binary_and behavior."""
    state = VMState(stack=[6, 3], pc=0)
    result = arithmetic.handle_binary_and(_instr("BINARY_AND"), state, OpcodeDispatcher())
    assert isinstance(result.new_states[0].peek(), SymbolicValue)


def test_handle_binary_or() -> None:
    """Test handle_binary_or behavior."""
    state = VMState(stack=[4, 1], pc=0)
    result = arithmetic.handle_binary_or(_instr("BINARY_OR"), state, OpcodeDispatcher())
    assert isinstance(result.new_states[0].peek(), SymbolicValue)


def test_handle_binary_xor() -> None:
    """Test handle_binary_xor behavior."""
    state = VMState(stack=[7, 1], pc=0)
    result = arithmetic.handle_binary_xor(_instr("BINARY_XOR"), state, OpcodeDispatcher())
    assert isinstance(result.new_states[0].peek(), SymbolicValue)


def test_handle_binary_op() -> None:
    """Test handle_binary_op behavior."""
    state = VMState(stack=[5, 6], pc=0)
    result = arithmetic.handle_binary_op(_instr("BINARY_OP", argrepr="+"), state, OpcodeDispatcher())
    assert result.terminal is False
    assert isinstance(result.new_states[0].peek(), SymbolicValue)
