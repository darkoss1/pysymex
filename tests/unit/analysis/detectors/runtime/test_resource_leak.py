"""Tests for pysymex/analysis/detectors/runtime/resource_leak.py."""

from __future__ import annotations

import dis
import time
from typing import cast

import z3

from pysymex.typing import StackValue
from pysymex.analysis.detectors.runtime.resource_leak import ResourceLeakDetector
from pysymex.core.solver.engine.context import active_incremental_solver
from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.state.types import CallFrame, wrap_cow_dict
from pysymex.core.state.record import VMState
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue


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


class TestResourceLeakDetector:
    """Test suite for pysymex.analysis.detectors.runtime.ResourceLeakDetector."""

    def test_check_tracks_open_and_reports_on_return(self) -> None:
        """Report RESOURCE_LEAK when an opened resource is not closed before return."""
        detector = ResourceLeakDetector()
        call_open = _make_instruction("CALL", arg=1, argval=1)
        return_instr = _make_instruction("RETURN_VALUE")
        state = VMState(stack=[open, "virtual"], path_constraints=[], pc=1)

        detector.check(state, call_open, lambda _constraints: True)
        issue = detector.check(state, return_instr, lambda _constraints: True)

        assert issue is not None

    def test_check_ignores_zero_argument_builtin_open(self) -> None:
        """Do not count builtin open() calls that CPython rejects before opening."""
        detector = ResourceLeakDetector()
        call_open = _make_instruction("CALL", arg=0, argval=0)
        return_instr = _make_instruction("RETURN_VALUE")
        state = VMState(stack=[open], path_constraints=[], pc=1)

        detector.check(state, call_open, lambda _constraints: True)
        issue = detector.check(state, return_instr, lambda _constraints: True)

        assert issue is None
        assert state.open_resources == 0

    def test_check_does_not_report_when_resource_closed(self) -> None:
        """Return None when close call balances previously opened resource."""
        detector = ResourceLeakDetector()
        call_open = _make_instruction("CALL", arg=1, argval=1)
        call_close = _make_instruction("CALL", arg=0, argval=0)
        return_instr = _make_instruction("RETURN_VALUE")

        class _CloseCallable:
            """Callable object with a close-like name for detector resolution."""

            __name__ = "close"

            def __call__(self) -> None:
                return None

        state = VMState(stack=[open, "virtual"], path_constraints=[], pc=1)
        detector.check(state, call_open, lambda _constraints: True)
        state.stack = [cast(StackValue, _CloseCallable())]
        detector.check(state, call_close, lambda _constraints: True)
        issue = detector.check(state, return_instr, lambda _constraints: True)
        assert issue is None

    def test_check_ignores_nested_function_return(self) -> None:
        """Return None for nested helper returns because caller may close resources later."""
        detector = ResourceLeakDetector()
        call_open = _make_instruction("CALL", arg=1, argval=1)
        return_instr = _make_instruction("RETURN_VALUE")
        state = VMState(stack=[open, "virtual"], path_constraints=[], pc=1)
        state.call_stack.append(
            CallFrame(
                function_name="caller",
                return_pc=0,
                local_vars=wrap_cow_dict({}),
                stack_depth=0,
                caller_instructions=None,
                summary_builder=None,
            )
        )

        detector.check(state, call_open, lambda _constraints: True)
        issue = detector.check(state, return_instr, lambda _constraints: True)
        assert issue is None

    def test_check_treats_before_with_as_managed_cleanup(self) -> None:
        """Return None at function return when open resource is transferred into with-context."""
        detector = ResourceLeakDetector()
        call_open = _make_instruction("CALL", arg=1, argval=1)
        before_with = _make_instruction("BEFORE_WITH")
        return_instr = _make_instruction("RETURN_VALUE")
        state = VMState(stack=[open, "virtual"], path_constraints=[], pc=1)
        detector.check(state, call_open, lambda _constraints: True)
        detector.check(state, before_with, lambda _constraints: True)
        issue = detector.check(state, return_instr, lambda _constraints: True)
        assert issue is None

    def test_check_maintains_path_local_open_count_on_fork(self) -> None:
        """Keep open resource counters isolated across forked execution paths."""
        detector = ResourceLeakDetector()
        call_open = _make_instruction("CALL", arg=1, argval=1)
        call_close = _make_instruction("CALL", arg=0, argval=0)

        class _CloseCallable:
            """Callable object with a close-like name for detector resolution."""

            __name__ = "close"

            def __call__(self) -> None:
                return None

        state_left = VMState(stack=[open, "virtual"], path_constraints=[], pc=1)
        detector.check(state_left, call_open, lambda _constraints: True)

        state_right = state_left.fork()
        state_right.stack = [cast(StackValue, _CloseCallable())]
        detector.check(state_right, call_close, lambda _constraints: True)

        assert state_left.open_resources == 1
        assert state_right.open_resources == 0

    def test_check_tracks_wrapped_open_call_as_resource_open(self) -> None:
        """Report RESOURCE_LEAK when wrapper function name ends with open and is unclosed."""
        detector = ResourceLeakDetector()
        call_open = _make_instruction("CALL", arg=0, argval=0)
        return_instr = _make_instruction("RETURN_VALUE")

        class _WrappedOpenCallable:
            __name__ = "wrapped_open"

            def __call__(self) -> None:
                return None

        state = VMState(stack=[_WrappedOpenCallable()], path_constraints=[], pc=1)
        detector.check(state, call_open, lambda _constraints: True)
        issue = detector.check(state, return_instr, lambda _constraints: True)
        assert issue is not None

    def test_check_tracks_unknown_callable_with_literal_symbolic_open_signature(self) -> None:
        """Report RESOURCE_LEAK when unknown callable uses open-like symbolic literal arguments."""
        detector = ResourceLeakDetector()
        call_open = _make_instruction("CALL", arg=2, argval=2)
        return_instr = _make_instruction("RETURN_VALUE")
        callable_signature_name = "('path', 'str', 'mode', 'str', 'return', '_Handle')"
        callable_value = SymbolicValue.symbolic(callable_signature_name)[0]
        path_arg = SymbolicString.symbolic("'virtual'")[0]
        mode_arg = SymbolicString.symbolic("'w'")[0]
        state = VMState(
            stack=[callable_value, SymbolicNone(), path_arg, mode_arg],
            path_constraints=[],
            pc=1,
        )
        detector.check(state, call_open, lambda _constraints: True)
        issue = detector.check(state, return_instr, lambda _constraints: True)
        assert issue is not None

    def test_check_does_not_report_definite_issue_on_solver_unknown(self) -> None:
        """Solver UNKNOWN must not become a definite resource-leak issue."""
        detector = ResourceLeakDetector()
        return_instr = _make_instruction("RETURN_VALUE")
        state = VMState(stack=[], path_constraints=[z3.Bool("resource_path")], pc=2)
        state.open_resources = 1
        solver = IncrementalSolver(timeout_ms=1000)
        solver.set_deadline(time.perf_counter() - 1.0)
        token = active_incremental_solver.set(solver)
        try:
            issue = detector.check(state, return_instr, lambda _constraints: True)
        finally:
            active_incremental_solver.reset(token)

        assert issue is None
        assert state.open_resources == 1
