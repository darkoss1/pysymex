"""Tests for pysymex/analysis/detectors/logical/__init__.py."""

from __future__ import annotations

import dis
import z3
from pysymex.analysis.detectors import DetectorRegistry, IssueKind
from pysymex.analysis.detectors.logical import create_logic_detector
from pysymex.analysis.detectors.logical.base import LogicalContradictionDetector
from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.config.settings import ExecutionConfig


def MockInstr(
    opname: str, argval: object = None, argrepr: str = "", arg: int = 0, offset: int = 10
) -> dis.Instruction:
    """Create deterministic synthetic dis instructions for logical detector tests."""

    def _dummy() -> None:
        """Provide a stable template source instruction."""
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


def test_create_logic_detector_exists() -> None:
    """Test create_logic_detector behavior."""
    assert callable(create_logic_detector)


def test_create_logic_detector_registers_all_tier_rules() -> None:
    """Logical detector factory registers all intended rules across tiers."""
    detector = create_logic_detector()
    assert len(detector.rules) == 24


def test_create_logic_detector_composition_reports_contradiction() -> None:
    """Composed logical detector flags an unsatisfiable branch in real detector flow."""
    detector = create_logic_detector(report_infeasible_branches=True)
    condition, condition_constraint = SymbolicValue.symbolic_bool("condition")
    state = VMState(stack=[condition], path_constraints=[condition_constraint], pc=10)
    state = state.add_constraint(condition.could_be_truthy())
    instruction = MockInstr("POP_JUMP_IF_TRUE", argval=2, offset=10)

    def _is_sat(constraints: list[z3.BoolRef]) -> bool:
        solver = z3.Solver()
        solver.add(constraints)
        return solver.check() == z3.sat

    issue = detector.check(state, instruction, _is_sat)
    assert issue is not None


def test_create_logic_detector_default_does_not_report_pruned_branch() -> None:
    """Default logical detector mode does not turn normal branch pruning into issues."""
    detector = create_logic_detector()
    condition, condition_constraint = SymbolicValue.symbolic_bool("condition")
    state = VMState(stack=[condition], path_constraints=[condition_constraint], pc=10)
    state = state.add_constraint(condition.could_be_truthy())
    instruction = MockInstr("POP_JUMP_IF_TRUE", argval=2, offset=10)
    solver_calls = 0

    def _is_sat(_constraints: list[z3.BoolRef]) -> bool:
        nonlocal solver_calls
        solver_calls += 1
        return False

    issue = detector.check(state, instruction, _is_sat)
    assert issue is None
    assert solver_calls == 0


def test_create_logic_detector_audit_mode_ignores_unclassified_unsat() -> None:
    """Audit mode reports only classified contradictions, not arbitrary unsat edges."""
    detector = create_logic_detector(report_infeasible_branches=True)
    condition, _condition_constraint = SymbolicValue.symbolic_bool("condition")
    state = VMState(stack=[condition], path_constraints=[], pc=10)
    instruction = MockInstr("POP_JUMP_IF_TRUE", argval=2, offset=10)

    def _is_sat(_constraints: list[z3.BoolRef]) -> bool:
        return False

    issue = detector.check(state, instruction, _is_sat)
    assert issue is None


def test_registered_default_logical_detector_does_not_report_normal_branch_pruning() -> None:
    """Activating the default logical detector keeps path pruning diagnostic-free and cheap."""

    def guarded_branch(x: int) -> int:
        if x > 0:
            return x + 1
        return x - 1

    detector = LogicalContradictionDetector()
    registry = DetectorRegistry()
    registry.register_fn(detector.as_fn(), detector.to_info())
    executor = SymbolicExecutor(
        config=ExecutionConfig(
            max_paths=4,
            max_iterations=40,
        ),
        detector_registry=registry,
    )

    result = executor.execute_function(guarded_branch, symbolic_args={"x": "int"})
    assert all(issue.kind is not IssueKind.LOGICAL_CONTRADICTION for issue in result.issues)
    detector_queries = result.solver_stats["detector_queries"]
    assert isinstance(detector_queries, dict)
    assert detector_queries["cache_misses"] == 0
    assert detector_queries["cache_hits"] == 0
