from __future__ import annotations

import dis

import z3

from pysymex.core.state.record import VMState
from pysymex.core.types.containers.sequences import SymbolicIterator
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.common.control.flow import handle_common_for_iter


def _instr(opname: str, argval: object = None, offset: int = 0) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval, offset=offset)


def _solver_status(state: VMState) -> z3.CheckSatResult:
    solver = z3.Solver()
    solver.add(*state.path_constraints.to_list())
    return solver.check()


def _run_string_for_iter(
    *, source: SymbolicString, source_constraint: z3.BoolRef, index: int, length: int
) -> list[VMState]:
    dispatcher = OpcodeDispatcher()
    for_iter = _instr("FOR_ITER", 10, offset=0)
    dispatcher.set_instructions([for_iter, _instr("NOP", offset=10)])
    state = VMState(
        stack=[SymbolicIterator("string_iter", source, index=index)],
        path_constraints=[source_constraint, source.z3_len == length],
        pc=0,
    )

    return handle_common_for_iter(for_iter, state, dispatcher).new_states


def test_for_iter_over_symbolic_string_yields_single_character_slice() -> None:
    source, source_constraint = SymbolicString.symbolic("source")

    states = _run_string_for_iter(
        source=source,
        source_constraint=source_constraint,
        index=0,
        length=2,
    )

    assert len(states) == 1
    continue_state = states[0]
    yielded = continue_state.stack[-1]
    assert isinstance(yielded, SymbolicString)
    advanced = continue_state.stack[-2]
    assert isinstance(advanced, SymbolicIterator)
    assert advanced.index == 1
    assert _solver_status(continue_state) == z3.sat

    solver = z3.Solver()
    solver.add(
        *continue_state.path_constraints.to_list(),
        yielded.z3_str != z3.SubString(source.z3_str, z3.IntVal(0), z3.IntVal(1)),
    )
    assert solver.check() == z3.unsat


def test_for_iter_over_symbolic_string_respects_constrained_length_exit() -> None:
    source, source_constraint = SymbolicString.symbolic("source")

    states = _run_string_for_iter(
        source=source,
        source_constraint=source_constraint,
        index=2,
        length=2,
    )

    assert len(states) == 1
    exit_state = states[0]
    assert _solver_status(exit_state) == z3.sat
