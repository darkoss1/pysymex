"""Tests for pysymex/analysis/detectors/runtime/attribute_error.py."""

from __future__ import annotations

import dis

import z3

from pysymex.analysis.detectors.runtime.attribute_error import AttributeErrorDetector
from pysymex.core.state import VMState
from pysymex.core.types.containers import SymbolicObject
from pysymex.core.types.scalars import SymbolicValue


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


class TestAttributeErrorDetector:
    """Test suite for pysymex.analysis.detectors.base.AttributeErrorDetector."""

    def test_check_ignores_empty_stack(self) -> None:
        """Return None when there is no object to inspect on the VM stack."""
        detector = AttributeErrorDetector()
        instruction = _make_instruction("LOAD_ATTR", "missing")
        state = VMState(stack=[], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is None

    def test_check_reports_missing_attr_for_concrete_int(self) -> None:
        """Report AttributeError when a concrete int is accessed with an invalid attribute."""
        detector = AttributeErrorDetector()
        instruction = _make_instruction("LOAD_ATTR", "not_a_real_attr")
        state = VMState(stack=[1], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_ignores_valid_attr_for_concrete_int(self) -> None:
        """Return None when the concrete primitive actually supports the attribute."""
        detector = AttributeErrorDetector()
        instruction = _make_instruction("LOAD_ATTR", "bit_length")
        state = VMState(stack=[1], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is None

    def test_check_reports_missing_attr_for_symbolic_int(self) -> None:
        """Report AttributeError for known symbolic int values with invalid attribute names."""
        detector = AttributeErrorDetector()
        instruction = _make_instruction("LOAD_ATTR", "not_a_real_attr")
        symbolic_int = SymbolicValue.from_const(7)
        state = VMState(stack=[symbolic_int], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_ignores_unknown_polymorphic_symbolic_value(self) -> None:
        """Return None for unconstrained symbolic values to avoid noisy false positives."""
        detector = AttributeErrorDetector()
        instruction = _make_instruction("LOAD_ATTR", "not_a_real_attr")
        symbolic_value, type_constraint = SymbolicValue.symbolic("poly_value")
        state = VMState(stack=[symbolic_value], path_constraints=[type_constraint], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is None

    def test_check_ignores_symbolic_object_with_unknown_shape(self) -> None:
        """Return None when a heap reference has no known structural type."""
        detector = AttributeErrorDetector()
        instruction = _make_instruction("LOAD_ATTR", "domain_specific_attr")
        symbolic_object = SymbolicObject("self", 1, z3.IntVal(1), {1})
        state = VMState(stack=[symbolic_object], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is None

    def test_check_ignores_internal_symbolic_attribute_placeholder(self) -> None:
        """Synthetic self/cls attribute placeholders are unknown, not definite AttributeError."""
        detector = AttributeErrorDetector()
        instruction = _make_instruction("LOAD_ATTR", "not_a_real_attr")
        symbolic_attr, type_constraint = SymbolicValue.symbolic("self.ready")
        state = VMState(stack=[symbolic_attr], path_constraints=[type_constraint], pc=1)

        issue = detector.check(state, instruction, lambda _constraints: True)

        assert issue is None
