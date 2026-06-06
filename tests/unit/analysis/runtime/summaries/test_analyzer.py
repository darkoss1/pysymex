import time

from pytest import MonkeyPatch
import z3

from pysymex.analysis.runtime.summaries.analyzer import SummaryAnalyzer
from pysymex.analysis.runtime.summaries.builder import SummaryBuilder
from pysymex.analysis.runtime.summaries.builtins import register_builtin_summaries
from pysymex.analysis.runtime.summaries.registry import SummaryRegistry
from pysymex.analysis.runtime.summaries.types import PreconditionCheckStatus
from pysymex.core.solver.engine.context import active_incremental_solver
from pysymex.core.solver.engine.incremental import IncrementalSolver


class TestSummaryAnalyzer:
    """Test suite for pysymex.analysis.runtime.summaries.analyzer.SummaryAnalyzer."""

    def test_is_pure(self) -> None:
        """Test is_pure behavior."""
        register_builtin_summaries()
        a = SummaryAnalyzer()
        assert a.is_pure("builtins.len") is True

    def test_may_modify_globals(self) -> None:
        """Test may_modify_globals behavior."""
        register_builtin_summaries()
        a = SummaryAnalyzer()
        assert a.may_modify_globals("builtins.print") is True

    def test_get_called_functions(self) -> None:
        """Test get_called_functions behavior."""
        a = SummaryAnalyzer()
        assert isinstance(a.get_called_functions("f"), set)

    def test_get_transitive_calls(self) -> None:
        """Test get_transitive_calls behavior."""
        a = SummaryAnalyzer()
        assert isinstance(a.get_transitive_calls("f"), set)

    def test_check_preconditions(self) -> None:
        """Test check_preconditions behavior."""
        a = SummaryAnalyzer()
        ok, ce = a.check_preconditions("missing", [], [])
        assert ok is True
        assert ce is None

    def test_check_preconditions_proves_satisfied_with_unsat_violation(self) -> None:
        registry = SummaryRegistry()
        summary = (
            SummaryBuilder("requires_positive")
            .add_parameter("x", "int")
            .require(z3.Int("x") > 0)
            .build()
        )
        registry.register(summary)
        analyzer = SummaryAnalyzer(registry)
        arg = z3.Int("summary_safe_arg")

        ok, ce = analyzer.check_preconditions("requires_positive", [arg], [arg > 2])

        assert ok is True
        assert ce is None

    def test_check_preconditions_returns_counterexample_for_definite_violation(self) -> None:
        registry = SummaryRegistry()
        summary = (
            SummaryBuilder("requires_positive")
            .add_parameter("x", "int")
            .require(z3.Int("x") > 0)
            .build()
        )
        registry.register(summary)
        analyzer = SummaryAnalyzer(registry)
        arg = z3.Int("summary_violation_arg")

        ok, ce = analyzer.check_preconditions("requires_positive", [arg], [arg < 0])

        assert ok is False
        assert ce is not None

    def test_check_preconditions_does_not_accept_solver_unknown_as_satisfied(self) -> None:
        registry = SummaryRegistry()
        summary = (
            SummaryBuilder("requires_positive")
            .add_parameter("x", "int")
            .require(z3.Int("x") > 0)
            .build()
        )
        registry.register(summary)
        analyzer = SummaryAnalyzer(registry)
        arg = z3.Int("summary_unknown_arg")
        solver = IncrementalSolver(timeout_ms=1000)
        solver.set_deadline(time.perf_counter() - 1.0)
        token = active_incremental_solver.set(solver)
        try:
            ok, ce = analyzer.check_preconditions("requires_positive", [arg], [])
        finally:
            active_incremental_solver.reset(token)

        assert ok is False
        assert ce is None

    def test_check_preconditions_result_marks_solver_unknown_explicitly(self) -> None:
        registry = SummaryRegistry()
        summary = (
            SummaryBuilder("requires_positive")
            .add_parameter("x", "int")
            .require(z3.Int("x") > 0)
            .build()
        )
        registry.register(summary)
        analyzer = SummaryAnalyzer(registry)
        arg = z3.Int("summary_unknown_result_arg")
        solver = IncrementalSolver(timeout_ms=1000)
        solver.set_deadline(time.perf_counter() - 1.0)
        token = active_incremental_solver.set(solver)
        try:
            result = analyzer.check_preconditions_result("requires_positive", [arg], [])
        finally:
            active_incremental_solver.reset(token)

        assert result.status == PreconditionCheckStatus.UNKNOWN
        assert result.is_satisfied is False
        assert result.counterexample is None
        assert result.reason == "Precondition check inconclusive: solver returned unknown"

    def test_check_preconditions_result_marks_definite_violation(self) -> None:
        registry = SummaryRegistry()
        summary = (
            SummaryBuilder("requires_positive")
            .add_parameter("x", "int")
            .require(z3.Int("x") > 0)
            .build()
        )
        registry.register(summary)
        analyzer = SummaryAnalyzer(registry)
        arg = z3.Int("summary_definite_violation_arg")

        result = analyzer.check_preconditions_result("requires_positive", [arg], [arg < 0])

        assert result.status == PreconditionCheckStatus.VIOLATED
        assert result.is_satisfied is False
        assert result.counterexample is not None
        assert result.reason is None

    def test_check_preconditions_result_marks_missing_model_as_unknown(
        self, monkeypatch: MonkeyPatch
    ) -> None:
        registry = SummaryRegistry()
        summary = (
            SummaryBuilder("requires_positive")
            .add_parameter("x", "int")
            .require(z3.Int("x") > 0)
            .build()
        )
        registry.register(summary)
        analyzer = SummaryAnalyzer(registry)
        arg = z3.Int("summary_missing_model_arg")

        def _missing_model(_constraints: list[z3.BoolRef]) -> None:
            return None

        monkeypatch.setattr("pysymex.analysis.runtime.summaries.analyzer.get_model", _missing_model)

        result = analyzer.check_preconditions_result("requires_positive", [arg], [arg < 0])

        assert result.status == PreconditionCheckStatus.UNKNOWN
        assert result.is_satisfied is False
        assert result.counterexample is None
        assert result.reason == (
            "Precondition violation is satisfiable but no counterexample model was available"
        )
