"""Tests for pysymex/_internal/analysis/detectors/runtime/attribute_error.py."""

from __future__ import annotations

import dis
import time

import z3

from pysymex._internal.analysis.detectors.runtime.errors.attribute.detector import (
    AttributeErrorDetector,
)
from pysymex._internal.core.classes.classes import SymbolicClass
from pysymex._internal.core.classes.instances import SymbolicInstance
from pysymex._internal.core.exceptions.objects import SymbolicException
from pysymex._internal.core.solver.engine.context import SolverContext
from pysymex._internal.core.solver.engine.incremental import IncrementalSolver
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue


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
    """Test suite for pysymex._internal.analysis.detectors.detector.AttributeErrorDetector."""

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

    def test_check_does_not_report_attribute_error_for_non_attribute_probe_failure(
        self,
    ) -> None:
        """Non-AttributeError descriptor/probe failures are unknown, not missing attributes."""

        class RaisesRuntime:
            def __call__(self) -> None:
                return None

            def __getattribute__(self, name: str) -> object:
                if name == "boom":
                    raise RuntimeError("not attribute absence")
                return object.__getattribute__(self, name)

        detector = AttributeErrorDetector()
        instruction = _make_instruction("LOAD_ATTR", "boom")
        state = VMState(stack=[RaisesRuntime()], path_constraints=[], pc=1)

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

    def test_check_ignores_modeled_pathlib_symbolic_path_attribute(self) -> None:
        """Modeled pathlib string carriers expose their synthetic path properties."""
        detector = AttributeErrorDetector()
        instruction = _make_instruction("LOAD_ATTR", "suffix")
        path_value, type_constraint = SymbolicString.symbolic("purepath_1")
        state = VMState(stack=[path_value], path_constraints=[type_constraint], pc=1)

        issue = detector.check(state, instruction, lambda _constraints: True)

        assert issue is None

    def test_check_reports_unknown_attribute_on_modeled_pathlib_symbolic_path(self) -> None:
        """Unsupported attributes on path-like carriers still report as missing."""
        detector = AttributeErrorDetector()
        instruction = _make_instruction("LOAD_ATTR", "not_a_path_property")
        path_value, type_constraint = SymbolicString.symbolic("purepath_1")
        state = VMState(stack=[path_value], path_constraints=[type_constraint], pc=1)

        issue = detector.check(state, instruction, lambda _constraints: True)

        assert issue is not None

    def test_check_ignores_retained_declared_descriptor_attribute(self) -> None:
        """Retained descriptor metadata proves the attribute exists on the class."""
        detector = AttributeErrorDetector()
        instruction = _make_instruction("LOAD_ATTR", "value")
        modeled_class = SymbolicClass("Record")
        setattr(modeled_class, "_pysymex_declared_descriptors", {"value": object()})
        receiver, type_constraint = SymbolicValue.symbolic("record")
        receiver.attach_modeled_object(SymbolicInstance(modeled_class, instance_id=1))
        state = VMState(stack=[receiver], path_constraints=[type_constraint], pc=1)

        issue = detector.check(state, instruction, lambda _constraints: True)

        assert issue is None

    def test_check_ignores_direct_exception_group_exceptions_attribute(self) -> None:
        """Retained ExceptionGroup payloads expose CPython's ``exceptions`` attribute."""
        detector = AttributeErrorDetector()
        instruction = _make_instruction("LOAD_ATTR", "exceptions")
        member = SymbolicException.concrete(RuntimeError, "boom")
        group = SymbolicException.concrete(ExceptionGroup, "group", [member])
        state = VMState(stack=[group], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, lambda _constraints: True)

        assert issue is None

    def test_check_ignores_modeled_exception_group_exceptions_attribute(self) -> None:
        """SymbolicValue carriers for ExceptionGroup payloads expose ``exceptions``."""
        detector = AttributeErrorDetector()
        instruction = _make_instruction("LOAD_ATTR", "exceptions")
        member = SymbolicException.concrete(RuntimeError, "boom")
        group = SymbolicException.concrete(ExceptionGroup, "group", [member])
        receiver = SymbolicValue.from_const(group)
        receiver.attach_modeled_object(group)
        state = VMState(stack=[receiver], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, lambda _constraints: True)

        assert issue is None

    def test_check_does_not_report_definite_issue_on_solver_unknown(self) -> None:
        """Solver UNKNOWN must not become a definite AttributeError issue."""
        detector = AttributeErrorDetector()
        instruction = _make_instruction("LOAD_ATTR", "not_a_real_attr")
        symbolic_int, type_constraint = SymbolicValue.symbolic_int("unknown_attr_target")
        deadline_probe = z3.Int("deadline_probe")
        state = VMState(
            stack=[symbolic_int],
            path_constraints=[type_constraint, deadline_probe >= 0],
            pc=7,
        )
        solver = IncrementalSolver(timeout_ms=1000)
        solver.set_deadline(time.perf_counter() - 1.0)
        token = SolverContext.active.set(solver)
        try:
            issue = detector.check(state, instruction, lambda _constraints: True)
        finally:
            SolverContext.active.reset(token)

        assert issue is None
