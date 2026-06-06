"""Tests for pysymex/analysis/detectors/specialized/unreachable_code.py."""

from __future__ import annotations

import dis

import pytest
import z3

from pysymex.analysis.detectors.specialized.unreachable_code import UnreachableCodeDetector
from pysymex.core.solver.unsat import UnsatCoreResult
from pysymex.core.state.record import VMState


def _always_sat(constraints: list[z3.BoolRef]) -> bool:
    """Always return True for satisfiability checks."""
    _ = constraints
    return True


def _never_sat(constraints: list[z3.BoolRef]) -> bool:
    """Always return False for satisfiability checks."""
    _ = constraints
    return False


def _z3_is_sat(constraints: list[z3.BoolRef]) -> bool:
    """Return True only when Z3 proves the constraints satisfiable."""
    solver = z3.Solver()
    solver.add(*constraints)
    return solver.check() == z3.sat


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
        x = z3.Int("x")
        state = VMState(stack=[], path_constraints=[x > 0, x < 0], pc=1)

        issue = detector.check(state, instruction, _z3_is_sat)

        assert issue is not None
        assert issue.kind.name == "UNREACHABLE_CODE"
        assert issue.pc == 1
        assert issue.constraints

    def test_check_returns_none_when_path_is_satisfiable(self) -> None:
        """Return None when path constraints evaluate to True."""
        detector = UnreachableCodeDetector()
        instruction = _make_instruction("POP_JUMP_IF_FALSE")
        state = VMState(stack=[], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, _always_sat)

        assert issue is None

    def test_check_requires_unsat_core_evidence(self) -> None:
        """A false SAT callback result without an UNSAT core is not reportable evidence."""
        detector = UnreachableCodeDetector()
        instruction = _make_instruction("POP_JUMP_IF_FALSE")
        state = VMState(stack=[], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, _never_sat)

        assert issue is None

    def test_check_treats_sat_callback_failure_as_inconclusive(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A SAT callback failure must not become unreachable-code evidence."""
        detector = UnreachableCodeDetector()
        instruction = _make_instruction("POP_JUMP_IF_FALSE")
        state = VMState(stack=[], path_constraints=[], pc=1)

        def _solver_failure(_constraints: list[z3.BoolRef]) -> bool:
            raise z3.Z3Exception("solver unavailable")

        def _extract_core(_constraints: list[z3.BoolRef]) -> UnsatCoreResult:
            raise AssertionError("inconclusive callback failures must not extract cores")

        monkeypatch.setattr(
            "pysymex.analysis.detectors.specialized.unreachable_code.extract_unsat_core",
            _extract_core,
        )

        issue = detector.check(state, instruction, _solver_failure)

        assert issue is None

    def test_check_ignores_unrelated_opcode(self) -> None:
        """Return None if instruction is not a jump that requires satisfiability."""
        detector = UnreachableCodeDetector()
        instruction = _make_instruction("NOP")
        x = z3.Int("x")
        state = VMState(stack=[], path_constraints=[x > 0, x < 0], pc=1)

        issue = detector.check(state, instruction, _z3_is_sat)

        assert issue is None
