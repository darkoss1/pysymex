from __future__ import annotations

import dis

import z3

from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicNone, SymbolicString, SymbolicValue
from pysymex.execution.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.py313 import compare


def _instr(opname: str, argval: str | int = 0) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval)


def test_handle_compare_op() -> None:
    """Test handle_compare_op behavior."""
    left = SymbolicValue.from_const(4)
    right = SymbolicValue.from_const(2)
    state = VMState(stack=[left, right], pc=3)

    result = compare.handle_compare_op(_instr("COMPARE_OP", ">"), state, OpcodeDispatcher())

    assert len(result.new_states) == 1
    next_state = result.new_states[0]
    assert next_state.pc == 4
    top = next_state.peek()
    assert isinstance(top, SymbolicValue)
    solver = z3.Solver()
    solver.add(z3.Not(top.z3_bool))
    assert solver.check() == z3.unsat


def test_handle_is_op() -> None:
    """Test handle_is_op behavior."""
    state = VMState(stack=[SymbolicNone("n1"), SymbolicNone("n2")], pc=2)

    result = compare.handle_is_op(_instr("IS_OP", 0), state, OpcodeDispatcher())

    assert len(result.new_states) == 1
    top = result.new_states[0].peek()
    assert isinstance(top, SymbolicValue)
    assert z3.is_true(z3.simplify(top.z3_bool))


def test_handle_contains_op() -> None:
    """Test handle_contains_op behavior."""
    left = SymbolicString.from_const("py")
    right = SymbolicString.from_const("pysymex")
    state = VMState(stack=[left, right], pc=7)

    result = compare.handle_contains_op(_instr("CONTAINS_OP", 0), state, OpcodeDispatcher())

    assert len(result.new_states) == 1
    top = result.new_states[0].peek()
    assert isinstance(top, SymbolicValue)
    solver = z3.Solver()
    solver.add(z3.Not(top.z3_bool))
    assert solver.check() == z3.unsat
