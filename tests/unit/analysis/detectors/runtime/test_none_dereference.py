"""Tests for pysymex/analysis/detectors/runtime/none_dereference.py."""

from __future__ import annotations

import dis

import z3

from pysymex.analysis.detectors.runtime.none_dereference import (
    NoneDereferenceDetector,
    pure_check_none_deref,
)
from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicNone, SymbolicValue


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


class TestNoneDereferenceDetector:
    """Test suite for pysymex.analysis.detectors.base.NoneDereferenceDetector."""

    def test_check_reports_concrete_none_dereference(self) -> None:
        """Report NULL_DEREFERENCE when concrete None is dereferenced."""
        detector = NoneDereferenceDetector()
        instruction = _make_instruction("LOAD_ATTR", "missing")
        state = VMState(stack=[None], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_ignores_none_valid_attribute(self) -> None:
        """Return None when attribute exists on NoneType (e.g. __class__)."""
        detector = NoneDereferenceDetector()
        instruction = _make_instruction("LOAD_ATTR", "__class__")
        state = VMState(stack=[None], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is None

    def test_check_reports_symbolic_possible_none(self) -> None:
        """Report NULL_DEREFERENCE for symbolic values that can be None."""
        detector = NoneDereferenceDetector()
        instruction = _make_instruction("LOAD_ATTR", "missing")
        symbolic_value, type_constraint = SymbolicValue.symbolic("obj")
        state = VMState(stack=[symbolic_value], path_constraints=[type_constraint], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_routes_symbolic_none_query_through_supplied_solver(self) -> None:
        """Use the executor-provided solver hook for symbolic None checks."""
        detector = NoneDereferenceDetector()
        instruction = _make_instruction("LOAD_ATTR", "missing")
        symbolic_value, type_constraint = SymbolicValue.symbolic("hooked_obj")
        checker = _RecordingZ3Checker()
        state = VMState(stack=[symbolic_value], path_constraints=[type_constraint], pc=1)

        issue = detector.check(state, instruction, checker)

        assert issue is not None
        assert len(checker.calls) == 1

    def test_check_ignores_explicit_non_none_symbolic(self) -> None:
        """Return None when symbolic value is constrained away from None."""
        detector = NoneDereferenceDetector()
        instruction = _make_instruction("LOAD_ATTR", "missing")
        symbolic_value = SymbolicValue.from_const(1)
        state = VMState(stack=[symbolic_value], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, _RecordingZ3Checker())
        assert issue is None

    def test_check_ignores_file_handle_close_pattern(self) -> None:
        """Return None for file handle close calls to avoid known false positives."""
        detector = NoneDereferenceDetector()
        instruction = _make_instruction("LOAD_METHOD", "close")
        file_value, type_constraint = SymbolicValue.symbolic("file_1")
        state = VMState(stack=[file_value], path_constraints=[type_constraint], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is None

    def test_check_reports_subscript_on_none(self) -> None:
        """Report NULL_DEREFERENCE for BINARY_SUBSCR when target object is None."""
        detector = NoneDereferenceDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        state = VMState(stack=[None, 0], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_reports_load_super_attr_on_none(self) -> None:
        """Report NULL_DEREFERENCE for LOAD_SUPER_ATTR on None receivers."""
        detector = NoneDereferenceDetector()
        instruction = _make_instruction("LOAD_SUPER_ATTR", "missing")
        state = VMState(stack=[None], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_reports_delete_attr_on_none(self) -> None:
        """Report NULL_DEREFERENCE for DELETE_ATTR on None receivers."""
        detector = NoneDereferenceDetector()
        instruction = _make_instruction("DELETE_ATTR", "missing")
        state = VMState(stack=[None], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None


def test_pure_check_none_deref_exists() -> None:
    """Test pure_check_none_deref behavior."""
    assert callable(pure_check_none_deref)


def test_pure_check_none_deref_symbolic_none_reports_issue() -> None:
    """Return issue for direct SymbolicNone dereference."""
    issue = pure_check_none_deref(
        obj=SymbolicNone(),
        attr_name="missing",
        path_constraints=[],
        pc=3,
    )
    assert issue is not None
