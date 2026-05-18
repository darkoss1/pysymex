"""Tests for pysymex/analysis/detectors/runtime/index_error.py."""

from __future__ import annotations

import dis

import z3

from pysymex.analysis.detectors.runtime.index_error import (
    IndexErrorDetector,
    pure_check_index_bounds,
)
from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicString, SymbolicValue


class _RecordingZ3Checker:
    """Run real Z3 checks while recording detector query routing."""

    def __init__(self) -> None:
        self.calls: list[list[z3.BoolRef]] = []

    def __call__(self, constraints: list[z3.BoolRef]) -> bool:
        self.calls.append(constraints)
        solver = z3.Solver()
        solver.add(*constraints)
        return solver.check() == z3.sat


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
    """Test suite for pysymex.analysis.detectors.base.IndexErrorDetector."""

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


def test_pure_check_index_bounds_exists() -> None:
    """Test pure_check_index_bounds behavior."""
    assert callable(pure_check_index_bounds)
