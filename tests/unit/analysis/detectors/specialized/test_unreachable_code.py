"""Tests for pysymex/analysis/detectors/specialized/unreachable_code.py."""

from __future__ import annotations

import dis

import z3

from pysymex.analysis.detectors.specialized.unreachable_code import UnreachableCodeDetector
from pysymex.core.state import VMState


def _always_sat(constraints: list[z3.BoolRef]) -> bool:
    """Always return True for satisfiability checks."""
    _ = constraints
    return True


def _never_sat(constraints: list[z3.BoolRef]) -> bool:
    """Always return False for satisfiability checks."""
    _ = constraints
    return False


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


class TestUnreachableCodeDetector:
    """Test suite for specialized UnreachableCodeDetector behavior."""

    def test_check_returns_issue_when_path_is_unsatisfiable(self) -> None:
        """Report UNREACHABLE_CODE when path constraints evaluate to False."""
        detector = UnreachableCodeDetector()
        instruction = _make_instruction("POP_JUMP_IF_FALSE")
        state = VMState(stack=[], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, _never_sat)

        assert issue is not None
        assert issue.kind.name == "UNREACHABLE_CODE"
        assert issue.pc == 1

    def test_check_returns_none_when_path_is_satisfiable(self) -> None:
        """Return None when path constraints evaluate to True."""
        detector = UnreachableCodeDetector()
        instruction = _make_instruction("POP_JUMP_IF_FALSE")
        state = VMState(stack=[], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, _always_sat)

        assert issue is None

    def test_check_ignores_unrelated_opcode(self) -> None:
        """Return None if instruction is not a jump that requires satisfiability."""
        detector = UnreachableCodeDetector()
        assert "NOP" not in detector.relevant_opcodes
