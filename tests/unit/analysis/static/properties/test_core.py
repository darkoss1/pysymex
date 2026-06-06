from typing import cast

import z3
from pytest import MonkeyPatch

from pysymex.analysis.static.properties.arithmetic_verifier import ArithmeticVerifier
from pysymex.analysis.static.properties.equivalence import EquivalenceChecker
from pysymex.analysis.static.properties.model_values import extract_model_values_result
from pysymex.analysis.static.properties.solver_queries import (
    check_violation_query,
    proof_from_solver_result,
)
from pysymex.analysis.static.properties.types import (
    ProofReason,
    ProofStatus,
    PropertyKind,
    PropertySpec,
)
from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.solver.engine.results import SolverResult


def _double_expr(x: z3.ExprRef) -> z3.ExprRef:
    return x + x


def _twice_expr(x: z3.ExprRef) -> z3.ExprRef:
    return 2 * x


def _positive_expr(x: z3.ExprRef) -> z3.BoolRef:
    return x > 0


def _greater_than_five_expr(x: z3.ExprRef) -> z3.BoolRef:
    return x > 5


class TestPropertySolverQueries:
    """Tests for shared property proof query helpers."""

    def test_solver_add_failure_returns_unknown_proof(self, monkeypatch: MonkeyPatch) -> None:
        """Property encoding failures are inconclusive."""
        solver = IncrementalSolver()
        spec = PropertySpec(PropertyKind.EQUIVALENCE, "prop")

        def raising_add(*constraints: z3.BoolRef) -> None:
            _ = constraints
            raise z3.Z3Exception("forced property prover add failure")

        monkeypatch.setattr(solver, "add", raising_add)

        res = check_violation_query(solver, spec, {}, lambda: (z3.Not(z3.BoolVal(True)),))

        assert res.status is ProofStatus.UNKNOWN
        assert res.reason is ProofReason.SOLVER_UNKNOWN
        assert res.property.name == "prop"

    def test_violation_builder_failure_returns_query_exception_reason(self) -> None:
        """Violation-condition builder failures are distinct from solver UNKNOWN."""
        spec = PropertySpec(PropertyKind.EQUIVALENCE, "Builder Failure")
        solver = IncrementalSolver()

        def raising_builder() -> tuple[z3.BoolRef, ...]:
            raise z3.Z3Exception("forced violation builder failure")

        result = check_violation_query(solver, spec, {}, raising_builder)

        assert result.status is ProofStatus.UNKNOWN
        assert result.reason is ProofReason.QUERY_EXCEPTION

    def test_sat_without_model_returns_unknown_proof(self) -> None:
        """A SAT violation without model evidence is inconclusive."""
        spec = PropertySpec(PropertyKind.EQUIVALENCE, "Missing Model")
        x = z3.Int("property_missing_model_x")

        result = proof_from_solver_result(spec, {"x": x}, SolverResult.sat(None), 0.0)

        assert result.status is ProofStatus.UNKNOWN
        assert result.reason is ProofReason.MISSING_COUNTEREXAMPLE_MODEL
        assert result.counterexample is None

    def test_sat_with_model_eval_failure_returns_unknown_proof(self) -> None:
        """A SAT violation with unusable counterexample evidence is inconclusive."""
        spec = PropertySpec(PropertyKind.EQUIVALENCE, "Broken Model")
        x = z3.Int("property_broken_model_x")

        class _ModelWithFailingEval:
            def eval(
                self,
                expr: z3.ExprRef,
                *,
                model_completion: bool = False,
            ) -> z3.ExprRef:
                _ = expr
                _ = model_completion
                raise z3.Z3Exception("forced property model evaluation failure")

        model = cast("z3.ModelRef", _ModelWithFailingEval())

        result = proof_from_solver_result(spec, {"x": x}, SolverResult.sat(model), 0.0)

        assert result.status is ProofStatus.UNKNOWN
        assert result.reason is ProofReason.INCOMPLETE_COUNTEREXAMPLE
        assert result.counterexample is None

        extraction = extract_model_values_result(model, {"x": x})
        assert extraction.complete is False
        assert extraction.failed_variables == ("x",)

    def test_solver_unknown_has_machine_readable_reason(self) -> None:
        """A solver UNKNOWN proof result records why no proof status is definite."""
        spec = PropertySpec(PropertyKind.EQUIVALENCE, "Unknown Proof")

        result = proof_from_solver_result(spec, {}, SolverResult.unknown(), 0.0)

        assert result.status is ProofStatus.UNKNOWN
        assert result.reason is ProofReason.SOLVER_UNKNOWN

    def test_elapsed_timeout_has_machine_readable_reason(self) -> None:
        """Elapsed timeout classification records timeout instead of generic unknown."""
        spec = PropertySpec(PropertyKind.EQUIVALENCE, "Timeout Proof")

        result = proof_from_solver_result(
            spec,
            {},
            SolverResult.unknown(),
            0.2,
            timeout_ms=100,
            classify_elapsed_timeout=True,
        )

        assert result.status is ProofStatus.TIMEOUT
        assert result.reason is ProofReason.ELAPSED_TIMEOUT


class TestArithmeticVerifier:
    """Test suite for pysymex.analysis.static.properties.arithmetic_verifier.ArithmeticVerifier."""

    def test_check_overflow(self) -> None:
        """Test check_overflow behavior."""
        v = ArithmeticVerifier()
        x = z3.Int("x")
        y = z3.Int("y")
        expr = x + y
        res = v.check_overflow(expr, {"x": x, "y": y})
        assert res.is_disproven is True

    def test_check_underflow(self) -> None:
        """Test check_underflow behavior."""
        v = ArithmeticVerifier()
        x = z3.Int("x")
        y = z3.Int("y")
        expr = x - y
        res = v.check_underflow(expr, {"x": x, "y": y})
        assert res.is_disproven is True

    def test_check_underflow_ignores_upper_bound_overflow(self) -> None:
        """Do not disprove underflow when constraints only allow values above the max."""
        v = ArithmeticVerifier(int_bits=8)
        x = z3.Int("underflow_upper_only")

        res = v.check_underflow(x, {"x": x}, [x > v.int_max])

        assert res.is_proven is True
        assert res.property.name == "No Underflow"

    def test_check_division_safe(self) -> None:
        """Test check_division_safe behavior."""
        v = ArithmeticVerifier()
        x = z3.Int("x")
        y = z3.Int("y")
        res = v.check_division_safe(x, y, {"x": x, "y": y}, [y != 0])
        assert res.is_proven is True

    def test_check_array_bounds(self) -> None:
        """Test check_array_bounds behavior."""
        v = ArithmeticVerifier()
        idx = z3.Int("idx")
        res = v.check_array_bounds(idx, z3.IntVal(10), {"idx": idx}, [idx >= 0, idx < 10])
        assert res.is_proven is True

    def test_solver_add_failure_returns_unknown_proof(self, monkeypatch: MonkeyPatch) -> None:
        """Encoding failures are inconclusive, not escaped verifier errors."""
        v = ArithmeticVerifier()
        x = z3.Int("arithmetic_add_failure")

        def raising_add(*constraints: z3.BoolRef) -> None:
            _ = constraints
            raise z3.Z3Exception("forced arithmetic verifier add failure")

        monkeypatch.setattr(v.solver, "add", raising_add)

        res = v.check_overflow(x, {"x": x})

        assert res.status is ProofStatus.UNKNOWN
        assert res.reason is ProofReason.SOLVER_UNKNOWN
        assert res.property.name == "No Overflow"


class TestEquivalenceChecker:
    """Test suite for pysymex.analysis.static.properties.equivalence.EquivalenceChecker."""

    def test_check_equivalent(self) -> None:
        """Test check_equivalent behavior."""
        ec = EquivalenceChecker()
        res = ec.check_equivalent(_double_expr, _twice_expr, [z3.Int("x")])
        assert res.is_proven is True

    def test_check_refinement(self) -> None:
        """Test check_refinement behavior."""
        ec = EquivalenceChecker()
        res = ec.check_refinement(_positive_expr, _greater_than_five_expr, [z3.Int("x")])
        assert res.is_proven is True

    def test_solver_add_failure_returns_unknown_proof(self, monkeypatch: MonkeyPatch) -> None:
        """Equivalence encoding failures are inconclusive."""
        ec = EquivalenceChecker()
        x = z3.Int("equivalence_add_failure")

        def raising_add(*constraints: z3.BoolRef) -> None:
            _ = constraints
            raise z3.Z3Exception("forced equivalence add failure")

        monkeypatch.setattr(ec.solver, "add", raising_add)

        res = ec.check_equivalent(_double_expr, _twice_expr, [x])

        assert res.status is ProofStatus.UNKNOWN
        assert res.reason is ProofReason.SOLVER_UNKNOWN
        assert res.property.name == "Implementation Equivalence"
