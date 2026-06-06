"""Tests for pysymex/analysis/detectors/runtime/user_exception.py."""

from __future__ import annotations

import dis

import z3

from pysymex.analysis.detectors.runtime.user_exception import UserExceptionDetector
from pysymex.core.exceptions.objects import SymbolicException
from pysymex.core.state.record import VMState

from pysymex.analysis.detectors.detector.types import IssueKind


def _make_instruction(
    opname: str, argval: object = None, argrepr: str = "", arg: int = 0, offset: int = 10
) -> dis.Instruction:
    """Create a deterministic instruction for detector unit tests."""

    def _dummy() -> None:
        """Provide bytecode for a template instruction."""
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


class _MockSymbolicException:
    def __init__(self, name: str) -> None:
        self.name = name


class TestUserExceptionDetector:
    """Test suite for pysymex.analysis.detectors.runtime.user_exception.UserExceptionDetector."""

    def test_relevant_opcodes_are_raise_only(self) -> None:
        """Declare only opcodes that can represent explicit raises."""
        detector = UserExceptionDetector()

        assert detector.relevant_opcodes == frozenset({"RAISE_VARARGS", "RERAISE"})

    def test_check_ignores_non_raise_varargs(self) -> None:
        """Return None when the instruction is not RAISE_VARARGS."""
        detector = UserExceptionDetector()
        instruction = _make_instruction("LOAD_CONST", arg=1, argval=1)
        state = VMState(
            stack=[RuntimeError()],  # type: ignore[arg-type,list-item] # test mock
            path_constraints=[],
            pc=1,
            current_instructions=[instruction],
        )
        issue = detector.check(state, instruction, lambda _c: True)  # type: ignore[arg-type]  # test mock solver
        assert issue is None

    def test_check_ignores_zero_argc(self) -> None:
        """Return None when argc is zero and there is no active exception."""
        detector = UserExceptionDetector()
        instruction = _make_instruction("RAISE_VARARGS", arg=0, argval=0)
        state = VMState(
            stack=[RuntimeError()],  # type: ignore[arg-type,list-item] # test mock
            path_constraints=[],
            pc=1,
            current_instructions=[instruction],
        )
        issue = detector.check(state, instruction, lambda _c: True)  # type: ignore[arg-type]  # test mock solver
        assert issue is None

    def test_check_detects_zero_argc_with_active_exception(self) -> None:
        """A bare raise reports the exception currently handled by the VM."""
        detector = UserExceptionDetector()
        instruction = _make_instruction("RAISE_VARARGS", arg=0, argval=0)
        state = VMState(
            path_constraints=[],
            pc=1,
            current_instructions=[instruction],
            active_exception=SymbolicException.concrete(ZeroDivisionError),
        )

        issue = detector.check(state, instruction, lambda _c: True)

        assert issue is not None
        assert issue.kind == IssueKind.UNHANDLED_EXCEPTION
        assert "ZeroDivisionError" in issue.message

    def test_check_detects_cleanup_reraise_with_retained_exception(self) -> None:
        """Final RERAISE reports the exception retained by CPython cleanup bytecode."""
        detector = UserExceptionDetector()
        instruction = _make_instruction("RERAISE", arg=1, argval=1)
        state = VMState(
            path_constraints=[],
            pc=1,
            current_instructions=[instruction],
            pending_reraise_exception=SymbolicException.concrete(ZeroDivisionError),
        )

        issue = detector.check(state, instruction, lambda _c: True)

        assert issue is not None
        assert issue.kind == IssueKind.UNHANDLED_EXCEPTION
        assert "ZeroDivisionError" in issue.message

    def test_check_preserves_modeled_value_error_kind(self) -> None:
        """Internally modeled runtime ``ValueError`` keeps its specific issue kind."""
        detector = UserExceptionDetector()
        instruction = _make_instruction("RERAISE", arg=1, argval=1)
        state = VMState(
            path_constraints=[],
            pc=1,
            current_instructions=[instruction],
            pending_reraise_exception=SymbolicException.concrete(
                ValueError,
                "__len__() should return >= 0",
            ),
        )

        issue = detector.check(state, instruction, lambda _c: True)

        assert issue is not None
        assert issue.kind == IssueKind.VALUE_ERROR
        assert "__len__() should return >= 0" in issue.message

    def test_check_ignores_empty_stack(self) -> None:
        """Return None when the stack is smaller than argc."""
        detector = UserExceptionDetector()
        instruction = _make_instruction("RAISE_VARARGS", arg=1, argval=1)
        state = VMState(
            stack=[],
            path_constraints=[],
            pc=1,
            current_instructions=[instruction],
        )
        issue = detector.check(state, instruction, lambda _c: True)  # type: ignore[arg-type]  # test mock solver
        assert issue is None

    def test_check_detects_exception_class(self) -> None:
        """Report UNHANDLED_EXCEPTION when raising an exception class."""
        detector = UserExceptionDetector()
        instruction = _make_instruction("RAISE_VARARGS", arg=1, argval=1)
        state = VMState(
            stack=[RuntimeError],  # type: ignore[arg-type,list-item] # test mock
            path_constraints=[],
            pc=1,
            current_instructions=[instruction],
        )
        issue = detector.check(state, instruction, lambda _c: True)  # type: ignore[arg-type]  # test mock solver
        assert issue is not None
        assert issue.kind == IssueKind.UNHANDLED_EXCEPTION
        assert "RuntimeError" in issue.message

    def test_check_detects_exception_instance(self) -> None:
        """Report UNHANDLED_EXCEPTION when raising an exception instance."""
        detector = UserExceptionDetector()
        instruction = _make_instruction("RAISE_VARARGS", arg=1, argval=1)
        state = VMState(
            stack=[RuntimeError("boom")],  # type: ignore[arg-type,list-item] # test mock
            path_constraints=[],
            pc=1,
            current_instructions=[instruction],
        )
        issue = detector.check(state, instruction, lambda _c: True)  # type: ignore[arg-type]  # test mock solver
        assert issue is not None
        assert issue.kind == IssueKind.UNHANDLED_EXCEPTION
        assert "RuntimeError" in issue.message

    def test_check_detects_symbolic_exception(self) -> None:
        """Report UNHANDLED_EXCEPTION when raising a mock symbolic object named Error/Exception."""
        detector = UserExceptionDetector()
        instruction = _make_instruction("RAISE_VARARGS", arg=1, argval=1)
        state = VMState(
            stack=[_MockSymbolicException("MyCustomError")],  # type: ignore[arg-type,list-item] # test mock
            path_constraints=[],
            pc=1,
            current_instructions=[instruction],
        )
        issue = detector.check(state, instruction, lambda _c: True)  # type: ignore[arg-type]  # test mock solver
        assert issue is not None
        assert issue.kind == IssueKind.UNHANDLED_EXCEPTION
        assert "MyCustomError" in issue.message

    def test_check_normalizes_modeled_exception_instance_name(self) -> None:
        """Exception constructor model instance names report the exception type."""
        detector = UserExceptionDetector()
        instruction = _make_instruction("RAISE_VARARGS", arg=1, argval=1)
        state = VMState(
            stack=[_MockSymbolicException("RuntimeError_instance_4")],  # type: ignore[arg-type,list-item] # test mock
            path_constraints=[],
            pc=1,
            current_instructions=[instruction],
        )

        issue = detector.check(state, instruction, lambda _c: True)  # type: ignore[arg-type]  # test mock solver

        assert issue is not None
        assert issue.kind == IssueKind.UNHANDLED_EXCEPTION
        assert "RuntimeError" in issue.message
        assert "RuntimeError_instance" not in issue.message

    def test_check_ignores_non_exception_object(self) -> None:
        """Return None when the raised object is not identifiable as an exception."""
        detector = UserExceptionDetector()
        instruction = _make_instruction("RAISE_VARARGS", arg=1, argval=1)
        state = VMState(
            stack=[object()],  # type: ignore[arg-type,list-item] # test mock
            path_constraints=[],
            pc=1,
            current_instructions=[instruction],
        )
        issue = detector.check(state, instruction, lambda _c: True)  # type: ignore[arg-type]  # test mock solver
        assert issue is None

    def test_check_ignores_assertion_error(self) -> None:
        """Return None when the exception is an AssertionError (handled elsewhere)."""
        detector = UserExceptionDetector()
        instruction = _make_instruction("RAISE_VARARGS", arg=1, argval=1)
        state = VMState(
            stack=[AssertionError("boom")],  # type: ignore[arg-type,list-item] # test mock
            path_constraints=[],
            pc=1,
            current_instructions=[instruction],
        )
        issue = detector.check(state, instruction, lambda _c: True)  # type: ignore[arg-type]  # test mock solver
        assert issue is None

    def test_check_ignores_unsat_path(self) -> None:
        """Return None when solver returns False for path constraints."""
        detector = UserExceptionDetector()
        instruction = _make_instruction("RAISE_VARARGS", arg=1, argval=1)
        state = VMState(
            stack=[RuntimeError("boom")],  # type: ignore[arg-type,list-item] # test mock
            path_constraints=[],
            pc=1,
            current_instructions=[instruction],
        )
        issue = detector.check(state, instruction, lambda _c: False)  # type: ignore[arg-type]  # test mock solver
        assert issue is None

    def test_check_treats_solver_callback_failure_as_inconclusive(self) -> None:
        """Return None when path feasibility cannot be established."""
        detector = UserExceptionDetector()
        instruction = _make_instruction("RAISE_VARARGS", arg=1, argval=1)
        state = VMState(
            stack=[RuntimeError("boom")],  # type: ignore[arg-type,list-item] # test mock
            path_constraints=[],
            pc=1,
            current_instructions=[instruction],
        )

        def _solver_failure(_constraints: list[z3.BoolRef]) -> bool:
            raise z3.Z3Exception("solver unavailable")

        issue = detector.check(state, instruction, _solver_failure)

        assert issue is None

    def test_check_detects_raise_from_cause(self) -> None:
        """Report UNHANDLED_EXCEPTION when raising with a cause (argc=2)."""
        detector = UserExceptionDetector()
        instruction = _make_instruction("RAISE_VARARGS", arg=2, argval=2)
        # Stack order: [..., exception, cause]
        state = VMState(
            stack=[RuntimeError("boom"), ValueError("cause")],  # type: ignore[arg-type,list-item] # test mock
            path_constraints=[],
            pc=1,
            current_instructions=[instruction],
        )
        issue = detector.check(state, instruction, lambda _c: True)  # type: ignore[arg-type]  # test mock solver
        assert issue is not None
        assert issue.kind == IssueKind.UNHANDLED_EXCEPTION
        assert "RuntimeError" in issue.message
