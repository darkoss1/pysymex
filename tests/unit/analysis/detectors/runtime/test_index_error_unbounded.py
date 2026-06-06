"""Tests for IndexErrorDetector fallback unbounded-index checks."""

from __future__ import annotations

import dis

import z3

from pysymex.analysis.detectors.runtime.index_error.detector import IndexErrorDetector
from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.values import SymbolicValue


def _make_instruction(opname: str) -> dis.Instruction:
    def _dummy() -> None:
        return None

    template = next(dis.get_instructions(_dummy))
    return template._replace(opname=opname, opcode=dis.opmap.get(opname, 0))


def test_unbounded_index_skips_solver_for_concrete_small_index() -> None:
    """Concrete small integers cannot satisfy the unbounded-index fallback."""
    detector = IndexErrorDetector()
    container, container_constraint = SymbolicValue.symbolic("unknown_container")
    index = SymbolicValue.from_const(5)
    state = VMState(stack=[container, index], path_constraints=[container_constraint], pc=17)
    instruction = _make_instruction("BINARY_SUBSCR")

    def fail_if_called(_constraints: list[z3.BoolRef]) -> bool:
        raise AssertionError("small concrete index should not query the solver")

    issue = detector.check(state, instruction, fail_if_called)

    assert issue is None
