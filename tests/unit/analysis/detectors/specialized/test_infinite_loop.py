"""Tests for pysymex/analysis/detectors/specialized/infinite_loop.py."""

from __future__ import annotations

import dis
import z3

from pysymex.analysis.detectors.specialized.infinite_loop import InfiniteLoopDetector
from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicValue


def _always_sat(constraints: list[z3.BoolRef]) -> bool:
    """Always return True for satisfiability checks."""
    _ = constraints
    return True


def _make_instruction(
    opname: str, argval: object = None, argrepr: str = "", arg: int = 0, offset: int = 10
) -> dis.Instruction:
    """Create deterministic bytecode instructions for detector tests."""

    def _dummy() -> None:
        """Provide a stable instruction template."""
        return None

    template = next(dis.get_instructions(_dummy))
    return template._replace(
        opname=opname,
        opcode=dis.opmap.get(opname, 0),
        arg=arg,
        argval=argval,
        argrepr=argrepr,
        offset=offset,
    )


class TestInfiniteLoopDetector:
    """Test suite for specialized InfiniteLoopDetector behavior."""

    def test_check_reports_issue_when_backward_jump_exceeds_max_iterations(self) -> None:
        """Report INFINITE_LOOP when JUMP_BACKWARD counter strictly exceeds max allowed."""
        detector = InfiniteLoopDetector()
        detector._max_iterations = 2  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state
        instruction = _make_instruction("JUMP_BACKWARD")
        state = VMState(stack=[], path_constraints=[], pc=10)
        state.loop_counters[10] = 2  # next hit makes it 3 > 2

        issue = detector.check(state, instruction, _always_sat)

        assert issue is not None
        assert issue.kind.name == "INFINITE_LOOP"

    def test_check_returns_none_when_backward_jump_under_max_iterations(self) -> None:
        """Return None when JUMP_BACKWARD counter is under or equal to max iterations."""
        detector = InfiniteLoopDetector()
        detector._max_iterations = 2  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state
        instruction = _make_instruction("JUMP_BACKWARD")
        state = VMState(stack=[], path_constraints=[], pc=10)
        state.loop_counters[10] = 1  # next hit makes it 2 <= 2

        issue = detector.check(state, instruction, _always_sat)

        assert issue is None

    def test_check_reports_issue_when_conditional_backward_jump_has_concrete_true_condition(
        self,
    ) -> None:
        """Report INFINITE_LOOP when a backward conditional branch uses concrete True."""
        detector = InfiniteLoopDetector()
        instruction = _make_instruction("POP_JUMP_IF_TRUE", argval=5)  # target 5 < pc 10
        state = VMState(stack=[True], path_constraints=[], pc=10)

        issue = detector.check(state, instruction, _always_sat)

        assert issue is not None
        assert issue.kind.name == "INFINITE_LOOP"

    def test_check_returns_none_when_conditional_backward_jump_can_be_false(self) -> None:
        """Return None when POP_JUMP_IF_TRUE condition can evaluate to False."""
        detector = InfiniteLoopDetector()
        instruction = _make_instruction("POP_JUMP_IF_TRUE", argval=5)  # target 5 < pc 10
        cond, _ = SymbolicValue.symbolic_bool("cond")
        state = VMState(stack=[cond], path_constraints=[], pc=10)

        # Simulate is_satisfiable: Always true (so it can be True and can be False)
        issue = detector.check(state, instruction, _always_sat)

        assert issue is None

    def test_check_returns_none_when_conditional_jump_is_forward_and_always_true(self) -> None:
        """Return None for always-true forward conditional jumps (not a loop back-edge)."""
        detector = InfiniteLoopDetector()
        instruction = _make_instruction("POP_JUMP_IF_TRUE", argval=20)  # target 20 > pc 10
        cond, _ = SymbolicValue.symbolic_bool("cond")
        state = VMState(stack=[cond], path_constraints=[], pc=10)

        def _sat(constraints: list[z3.BoolRef]) -> bool:
            return not any("Not" in str(c) for c in constraints)

        issue = detector.check(state, instruction, _sat)

        assert issue is None

    def test_check_ignores_unrelated_opcode(self) -> None:
        """Return None when opcode does not control loop flow."""
        detector = InfiniteLoopDetector()
        instruction = _make_instruction("NOP")
        state = VMState(stack=[], path_constraints=[], pc=10)

        issue = detector.check(state, instruction, _always_sat)

        assert issue is None
