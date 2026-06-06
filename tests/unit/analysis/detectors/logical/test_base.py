"""Tests for pysymex/analysis/detectors/logical/base.py."""

import dis

import pytest
import z3

from pysymex.analysis.detectors.logical import create_logic_detector
from pysymex.analysis.detectors.logical.base import (
    ContradictionContext,
    LogicRule,
    LogicalContradictionDetector,
)
from pysymex.core.solver.unsat import UnsatCoreResult
from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.values import SymbolicValue


def MockInstr(
    opname: str, argval: object = None, argrepr: str = "", arg: int = 0, offset: int = 10
) -> dis.Instruction:
    import dis

    def _dummy() -> None:
        pass

    template = next(dis.get_instructions(_dummy))
    return template._replace(
        opname=opname,
        opcode=dis.opmap.get(opname, 0),
        arg=arg,
        argval=argval,
        argrepr=argrepr,
        offset=offset,
    )


class TestContradictionContext:
    """Test suite for ContradictionContext."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert ContradictionContext is not None
        assert ContradictionContext.__name__ == "ContradictionContext"


class TestLogicRule:
    """Test suite for LogicRule."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert LogicRule is not None
        assert LogicRule.__name__ == "LogicRule"


class TestLogicalContradictionDetector:
    """Test suite for LogicalContradictionDetector."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert LogicalContradictionDetector is not None
        assert LogicalContradictionDetector.__name__ == "LogicalContradictionDetector"

    def test_audit_mode_continues_after_unclassified_unsat_branch(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An unclassified first branch must not mask a classified second branch."""

        class _NegatedBranchRule(LogicRule):
            name = "Negated Branch"
            tier = 99

            def matches(self, ctx: ContradictionContext) -> bool:
                return z3.is_not(ctx.branch_cond)

        detector = LogicalContradictionDetector(report_infeasible_branches=True)
        detector.register_rule(_NegatedBranchRule())
        condition, condition_constraint = SymbolicValue.symbolic_bool("condition")
        state = VMState(stack=[condition], path_constraints=[condition_constraint], pc=10)
        instruction = MockInstr("POP_JUMP_IF_TRUE", argval=2, offset=10)

        def _is_sat(_constraints: list[z3.BoolRef]) -> bool:
            return False

        def _extract_core(constraints: list[z3.BoolRef]) -> UnsatCoreResult:
            branch = constraints[-1]
            return UnsatCoreResult(
                core=[branch],
                core_indices=[len(constraints) - 1],
                total_constraints=len(constraints),
            )

        monkeypatch.setattr(
            "pysymex.analysis.detectors.logical.base.extract_unsat_core", _extract_core
        )

        issue = detector.check(state, instruction, _is_sat)

        assert issue is not None
        assert "Negated Branch" in issue.message

    def test_audit_mode_requires_validated_unsat_core(self) -> None:
        """A solver-check false result without an UNSAT core is not reportable."""

        class _AlwaysRule(LogicRule):
            name = "Always"
            tier = 99

            def matches(self, ctx: ContradictionContext) -> bool:
                _ = ctx
                return True

        detector = LogicalContradictionDetector(report_infeasible_branches=True)
        detector.register_rule(_AlwaysRule())
        condition, condition_constraint = SymbolicValue.symbolic_bool("condition")
        state = VMState(stack=[condition], path_constraints=[condition_constraint], pc=10)
        instruction = MockInstr("POP_JUMP_IF_TRUE", argval=2, offset=10)

        def _unknown_or_unsat(_constraints: list[z3.BoolRef]) -> bool:
            return False

        issue = detector.check(state, instruction, _unknown_or_unsat)

        assert issue is None

    def test_audit_mode_treats_solver_callback_failure_as_inconclusive(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A SAT callback failure must not become a logical-contradiction report."""

        detector = LogicalContradictionDetector(report_infeasible_branches=True)
        condition, condition_constraint = SymbolicValue.symbolic_bool("condition")
        state = VMState(stack=[condition], path_constraints=[condition_constraint], pc=10)
        instruction = MockInstr("POP_JUMP_IF_TRUE", argval=2, offset=10)

        def _solver_failure(_constraints: list[z3.BoolRef]) -> bool:
            raise z3.Z3Exception("solver unavailable")

        def _extract_core(_constraints: list[z3.BoolRef]) -> UnsatCoreResult:
            raise AssertionError("inconclusive callback failures must not extract cores")

        monkeypatch.setattr(
            "pysymex.analysis.detectors.logical.base.extract_unsat_core", _extract_core
        )

        issue = detector.check(state, instruction, _solver_failure)

        assert issue is None

    def test_registered_rule_positive_shapes_are_solver_unsat(self) -> None:
        """Every curated positive logical rule shape must be a real Z3 contradiction."""
        x = z3.Int("x")
        y = z3.Int("y")
        z = z3.Int("z")
        b = z3.Bool("b")
        loop_i = z3.Int("loop_i")
        user_arg = z3.Int("user_arg")
        result_value = z3.Int("result_value")
        result_is_int = z3.Bool("result_is_int")
        result_is_str = z3.Bool("result_is_str")
        api_arg = z3.Int("api_arg")
        api_result = z3.Int("api_result")
        caller_arg = z3.Int("caller_arg")
        callee_result = z3.Int("callee_result")
        phase_active = z3.Bool("phase_active")
        file_open = z3.Bool("file_open")
        lock_held = z3.Bool("lock_held")

        cores_by_rule: dict[str, list[z3.BoolRef]] = {
            "RangeContradictionRule": [x > 5, x <= 5],
            "ParityContradictionRule": [x % 2 == 0, x % 2 == 1],
            "ModularContradictionRule": [x % 5 == 1, x % 5 == 2],
            "SelfContradictionRule": [z3.Not(x == x)],
            "ArithmeticImpossibilityRule": [2 * x == 1],
            "EqualityContradictionRule": [x == 1, x == 2],
            "ComplementContradictionRule": [b, z3.Not(b)],
            "AntisymmetryRule": [x > y, y >= x],
            "TriangleImpossibilityRule": [x >= 2, y >= 3, z >= 4, x + y + z < 9],
            "SumImpossibilityRule": [x >= 2, y >= 3, x + y < 5],
            "ProductSignContradictionRule": [x > 0, y > 0, x * y <= 0],
            "GcdImpossibilityRule": [x % 5 == 1, x % 5 == 2],
            "SequentialModularRule": [x % 5 == 1, x % 5 == 2, x * y == 10],
            "PostAssignmentContradictionRule": [x == 3, x > 3],
            "LoopInvariantViolationRule": [loop_i == loop_i + 1],
            "NarrowingContradictionRule": [x >= 0, x <= 10, x > 10],
            "ReturnTypeContradictionRule": [
                result_is_int,
                result_is_str,
                z3.Not(z3.And(result_is_int, result_is_str)),
            ],
            "PostconditionContradictionRule": [result_value >= 5, result_value < 5],
            "PreconditionImpossibilityRule": [user_arg >= 10, user_arg < 10],
            "ApiContractViolationRule": [api_arg > api_result, api_result >= api_arg],
            "NumericRangePropagationRule": [
                caller_arg < callee_result,
                callee_result <= caller_arg,
            ],
            "StateImpossibilityRule": [phase_active, z3.Not(phase_active)],
            "ResourceStateContradictionRule": [file_open, z3.Not(file_open)],
            "ConcurrencyContradictionRule": [lock_held, z3.Not(lock_held)],
        }

        detector = create_logic_detector(report_infeasible_branches=True)
        missing = {rule.__class__.__name__ for rule in detector.rules} - cores_by_rule.keys()
        assert missing == set()

        for rule in detector.rules:
            core = cores_by_rule[rule.__class__.__name__]
            solver = z3.Solver()
            solver.add(*core)
            assert solver.check() == z3.unsat, rule.__class__.__name__
            ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
            assert rule.matches(ctx), rule.__class__.__name__
