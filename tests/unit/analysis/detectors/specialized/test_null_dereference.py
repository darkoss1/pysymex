"""Tests for pysymex/analysis/detectors/specialized/null_dereference.py."""

from __future__ import annotations

import dis
import z3

from pysymex.analysis.detectors.specialized.null_dereference import (
    NullDereferenceDetector,
    pure_check_null_deref,
)
from pysymex.core.state import VMState


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


def test_pure_check_rejects_unsupported_opname() -> None:
    """Return None when operation is not an attribute or subscript load/store."""
    issue = pure_check_null_deref(None, "LOAD_CONST", [], 1, _always_sat, attr_name="attr")
    assert issue is None


def test_pure_check_rejects_empty_attr_name() -> None:
    """Return None when attribute name resolution yields an empty string."""
    issue = pure_check_null_deref(None, "LOAD_ATTR", [], 1, _always_sat, attr_name=None)
    assert issue is None


def test_pure_check_delegates_for_binary_subscr() -> None:
    """Delegate to runtime checks with __getitem__ when processing BINARY_SUBSCR."""
    # Since pure_check_none_deref will return an Issue if top is None
    issue = pure_check_null_deref(None, "BINARY_SUBSCR", [], 1, _always_sat, attr_name=None)
    assert issue is not None


def test_pure_check_delegates_for_load_attr() -> None:
    """Delegate to runtime checks with the provided attr_name when processing LOAD_ATTR."""
    issue = pure_check_null_deref(None, "LOAD_ATTR", [], 1, _always_sat, attr_name="test_field")
    assert issue is not None


class TestNullDereferenceDetector:
    """Test suite for specialized NullDereferenceDetector behavior."""

    def test_check_returns_none_for_unsupported_opcode(self) -> None:
        """Return None when the instruction is not relevant."""
        detector = NullDereferenceDetector()
        instruction = _make_instruction("LOAD_CONST")
        state = VMState(stack=[None], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, _always_sat)
        assert issue is None

    def test_check_returns_none_when_stack_is_empty(self) -> None:
        """Return None when executing an attribute read with an empty stack."""
        detector = NullDereferenceDetector()
        instruction = _make_instruction("LOAD_ATTR", argval="test")
        state = VMState(stack=[], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, _always_sat)
        assert issue is None

    def test_check_returns_none_for_binary_subscr_with_insufficient_stack(self) -> None:
        """Return None when executing BINARY_SUBSCR with fewer than 2 stack elements."""
        detector = NullDereferenceDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        state = VMState(stack=[None], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, _always_sat)
        assert issue is None

    def test_check_delegates_binary_subscr_to_pure_check(self) -> None:
        """Extract correct stack elements for BINARY_SUBSCR and delegate to pure check."""
        detector = NullDereferenceDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        # BINARY_SUBSCR pops index, then target. target is at -2.
        state = VMState(stack=[None, 5], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, _always_sat)
        assert issue is not None

    def test_check_delegates_load_attr_to_pure_check(self) -> None:
        """Extract correct stack element for LOAD_ATTR and delegate to pure check."""
        detector = NullDereferenceDetector()
        instruction = _make_instruction("LOAD_ATTR", argval="name")
        state = VMState(stack=[None], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, _always_sat)
        assert issue is not None
