"""Tests for pysymex/analysis/detectors/runtime/index_error.py."""

from __future__ import annotations

import dis
import time

import z3

from pysymex.analysis.detectors.runtime.index_error.bounds import (
    pure_check_index_bounds,
)
from pysymex.analysis.detectors.runtime.index_error.bounds import (
    pure_check_index_bounds as canonical_pure_check_index_bounds,
)
from pysymex.analysis.detectors.runtime.index_error.detector import (
    IndexErrorDetector,
)
from pysymex.analysis.detectors.runtime.index_error.detector import (
    IndexErrorDetector as CanonicalIndexErrorDetector,
)
from pysymex.core.solver.engine.context import active_incremental_solver
from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.state.record import VMState
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue


class _RecordingZ3Checker:
    """Run real Z3 checks while recording detector query routing."""

    def __init__(self) -> None:
        self.calls: list[list[z3.BoolRef]] = []

    def __call__(self, constraints: list[z3.BoolRef]) -> bool:
        self.calls.append(constraints)
        solver = z3.Solver()
        solver.add(*constraints)
        return solver.check() == z3.sat


def test_index_error_imports_use_canonical_objects() -> None:
    assert IndexErrorDetector is CanonicalIndexErrorDetector
    assert pure_check_index_bounds is canonical_pure_check_index_bounds


def _make_instruction(
    opname: str, argval: object = None, argrepr: str = "", arg: int = 0, offset: int = 10
) -> dis.Instruction:
    def _dummy() -> None:
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


class TestIndexErrorDetector:
    """Test suite for pysymex.analysis.detectors.detector.IndexErrorDetector."""

    def test_check_ignores_non_subscript_opcode(self) -> None:
        """Return None when instruction is not BINARY_SUBSCR."""
        detector = IndexErrorDetector()
        instruction = _make_instruction("LOAD_CONST")
        state = VMState(stack=[1, 2], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is None

    def test_check_skips_annotation_type_subscription(self) -> None:
        """Skip list[int]-style type annotation subscriptions."""
        detector = IndexErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        container = SymbolicValue.from_const(list)
        index = SymbolicValue.from_const(int)
        state = VMState(stack=[container, index], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is None

    def test_check_reports_unbounded_symbolic_index(self) -> None:
        """Report INDEX_ERROR when symbolic index can be arbitrarily large."""
        detector = IndexErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        container, container_constraint = SymbolicValue.symbolic("runtime_container")
        index, index_constraint = SymbolicValue.symbolic_int("huge_runtime_index")
        state = VMState(
            stack=[container, index],
            path_constraints=[container_constraint, index_constraint],
            pc=10,
        )
        checker = _RecordingZ3Checker()
        issue = detector.check(state, instruction, checker)
        assert issue is not None
        assert len(checker.calls) == 1

    def test_check_reports_out_of_bounds_for_list_pop_call(self) -> None:
        """Report INDEX_ERROR for list.pop(symbolic_index) call pattern."""
        detector = IndexErrorDetector()
        instruction = _make_instruction("CALL", arg=1, argval=1)

        class _PopCallable:
            __name__ = "list.pop"

            def __call__(self, index: object) -> object:
                return index

        index, index_constraint = SymbolicValue.symbolic_int("idx")
        state = VMState(
            stack=[_PopCallable(), [1, 2, 3], index],
            path_constraints=[index_constraint],
            pc=10,
        )
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_reports_empty_list_pop_without_index(self) -> None:
        """Report INDEX_ERROR for list.pop() when the receiver is known empty."""
        detector = IndexErrorDetector()
        instruction = _make_instruction("CALL", arg=0, argval=0)

        class _PopCallable:
            __name__ = "list.pop"

            def __call__(self) -> object:
                return None

        state = VMState(stack=[_PopCallable(), []], path_constraints=[], pc=10)

        issue = detector.check(state, instruction, _RecordingZ3Checker())

        assert issue is not None
        assert issue.kind.name == "INDEX_ERROR"

    def test_check_ignores_nonempty_list_pop_without_index(self) -> None:
        """Do not report INDEX_ERROR for list.pop() when the receiver is nonempty."""
        detector = IndexErrorDetector()
        instruction = _make_instruction("CALL", arg=0, argval=0)

        class _PopCallable:
            __name__ = "list.pop"

            def __call__(self) -> object:
                return None

        state = VMState(stack=[_PopCallable(), [1]], path_constraints=[], pc=10)

        issue = detector.check(state, instruction, _RecordingZ3Checker())

        assert issue is None

    def test_check_reports_symbolic_empty_list_pop_without_index(self) -> None:
        """Report INDEX_ERROR when symbolic list length can be zero for list.pop()."""
        detector = IndexErrorDetector()
        instruction = _make_instruction("CALL", arg=0, argval=0)

        class _PopCallable:
            __name__ = "list.pop"

            def __call__(self) -> object:
                return None

        symbolic_list, len_constraint = SymbolicList.symbolic("items")
        state = VMState(
            stack=[_PopCallable(), symbolic_list],
            path_constraints=[len_constraint],
            pc=10,
        )

        issue = detector.check(state, instruction, _RecordingZ3Checker())

        assert issue is not None
        assert issue.kind.name == "INDEX_ERROR"

    def test_check_ignores_guarded_nonempty_symbolic_list_pop_without_index(self) -> None:
        """Do not report list.pop() when constraints prove the symbolic list is nonempty."""
        detector = IndexErrorDetector()
        instruction = _make_instruction("CALL", arg=0, argval=0)

        class _PopCallable:
            __name__ = "list.pop"

            def __call__(self) -> object:
                return None

        symbolic_list, len_constraint = SymbolicList.symbolic("items")
        state = VMState(
            stack=[_PopCallable(), symbolic_list],
            path_constraints=[len_constraint, symbolic_list.z3_len > 0],
            pc=10,
        )

        issue = detector.check(state, instruction, _RecordingZ3Checker())

        assert issue is None

    def test_check_ignores_multi_argument_pop_call(self) -> None:
        """Only one-argument pop calls have sequence IndexError bounds semantics."""
        detector = IndexErrorDetector()
        instruction = _make_instruction("CALL", arg=2, argval=2)

        class _PopCallable:
            __name__ = "list.pop"

            def __call__(self, index: object, default: object) -> object:
                return index if default is None else default

        index, index_constraint = SymbolicValue.symbolic_int("pop_default_index")
        checker = _RecordingZ3Checker()
        state = VMState(
            stack=[_PopCallable(), [1, 2, 3], index, None],
            path_constraints=[index_constraint],
            pc=10,
        )

        issue = detector.check(state, instruction, checker)

        assert issue is None
        assert checker.calls == []

    def test_check_routes_bounds_query_through_supplied_solver(self) -> None:
        """Use the executor-provided solver hook for symbolic bounds checks."""
        detector = IndexErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        index, index_constraint = SymbolicValue.symbolic_int("hooked_index")
        checker = _RecordingZ3Checker()
        state = VMState(stack=[[1, 2, 3], index], path_constraints=[index_constraint], pc=1)

        issue = detector.check(state, instruction, checker)

        assert issue is not None
        assert len(checker.calls) == 1

    def test_check_reports_out_of_bounds_for_symbolic_tuple(self) -> None:
        """Report INDEX_ERROR for symbolic indexes into concrete tuple values."""
        detector = IndexErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        index, index_constraint = SymbolicValue.symbolic_int("tuple_index")
        container = SymbolicValue.from_const((1, 2, 3))
        checker = _RecordingZ3Checker()
        state = VMState(stack=[container, index], path_constraints=[index_constraint], pc=1)

        issue = detector.check(state, instruction, checker)

        assert issue is not None
        assert issue.kind.name == "INDEX_ERROR"
        assert len(checker.calls) == 1

    def test_check_reports_out_of_bounds_for_symbolic_bytes_constant(self) -> None:
        """Bytes constants loaded through SymbolicValue keep CPython index bounds."""
        detector = IndexErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        index, index_constraint = SymbolicValue.symbolic_int("bytes_index")
        container = SymbolicValue.from_const(b"abc")
        state = VMState(stack=[container, index], path_constraints=[index_constraint], pc=1)

        issue = detector.check(state, instruction, _RecordingZ3Checker())

        assert issue is not None
        assert issue.kind.name == "INDEX_ERROR"

    def test_check_reports_out_of_bounds_for_string_subscript(self) -> None:
        """Report INDEX_ERROR for symbolic indexes into concrete strings."""
        detector = IndexErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        index, index_constraint = SymbolicValue.symbolic_int("string_index")
        state = VMState(stack=["abc", index], path_constraints=[index_constraint], pc=1)

        issue = detector.check(state, instruction, _RecordingZ3Checker())

        assert issue is not None
        assert issue.kind.name == "INDEX_ERROR"

    def test_check_reports_out_of_bounds_for_symbolic_string_subscript(self) -> None:
        """Scanner-loaded string constants use SymbolicString and keep string bounds."""
        detector = IndexErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        index, index_constraint = SymbolicValue.symbolic_int("symbolic_string_index")
        state = VMState(
            stack=[SymbolicString.from_const("abc"), index],
            path_constraints=[index_constraint],
            pc=1,
        )

        issue = detector.check(state, instruction, _RecordingZ3Checker())

        assert issue is not None
        assert issue.kind.name == "INDEX_ERROR"

    def test_check_reports_out_of_bounds_for_delete_subscr(self) -> None:
        """DELETE_SUBSCR uses the same CPython sequence bounds as reads."""
        detector = IndexErrorDetector()
        instruction = _make_instruction("DELETE_SUBSCR")
        index, index_constraint = SymbolicValue.symbolic_int("delete_index")
        state = VMState(stack=[[1, 2, 3], index], path_constraints=[index_constraint], pc=1)

        issue = detector.check(state, instruction, _RecordingZ3Checker())

        assert issue is not None
        assert issue.kind.name == "INDEX_ERROR"

    def test_check_reports_inconclusive_bounds_issue_on_solver_unknown(self) -> None:
        """Solver UNKNOWN may surface only as a model-less low-confidence bounds issue."""
        detector = IndexErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        index, index_constraint = SymbolicValue.symbolic_int("unknown_bounds_index")
        solver = IncrementalSolver(timeout_ms=1000)
        solver.set_deadline(time.perf_counter() - 1.0)
        token = active_incremental_solver.set(solver)
        try:
            issue = detector.check(
                VMState(stack=[[1, 2, 3], index], path_constraints=[index_constraint], pc=1),
                instruction,
                lambda _constraints: True,
            )
        finally:
            active_incremental_solver.reset(token)

        assert issue is not None
        assert "Path feasibility inconclusive" in issue.message
        assert issue.model is None
        assert issue.get_counterexample() == {}
        assert issue.confidence == 0.5
        assert issue.likelihood == 0.5

    def test_check_does_not_report_unbounded_index_on_solver_unknown(self) -> None:
        """Unbounded-index fallback also requires model evidence."""
        detector = IndexErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        container, container_constraint = SymbolicValue.symbolic("unknown_container")
        index, index_constraint = SymbolicValue.symbolic_int("unknown_large_index")
        solver = IncrementalSolver(timeout_ms=1000)
        solver.set_deadline(time.perf_counter() - 1.0)
        token = active_incremental_solver.set(solver)
        try:
            issue = detector.check(
                VMState(
                    stack=[container, index],
                    path_constraints=[container_constraint, index_constraint],
                    pc=1,
                ),
                instruction,
                lambda _constraints: True,
            )
        finally:
            active_incremental_solver.reset(token)

        assert issue is None


def test_pure_check_index_bounds_exists() -> None:
    """Test pure_check_index_bounds behavior."""
    assert callable(pure_check_index_bounds)
