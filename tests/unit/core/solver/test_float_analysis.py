import time

import z3

from pysymex.config.floats import FloatPrecision, get_fp_sort
from pysymex.core.solver.engine.context import active_incremental_solver
from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.solver.floats.analysis import AccuracyAnalyzer, FloatAnalyzer
from pysymex.core.types.advanced_float import AdvancedSymbolicFloat


class TestFloatAnalyzer:
    def test_check_operation(self) -> None:
        analyzer = FloatAnalyzer()
        result = AdvancedSymbolicFloat("r")
        issues = analyzer.check_operation("add", result, [result], [])
        assert isinstance(issues, list)

    def test_check_operation_reports_only_model_backed_issues(self) -> None:
        analyzer = FloatAnalyzer()
        result = AdvancedSymbolicFloat("model_backed_nan_result")

        issues = analyzer.check_operation("add", result, [result], [result.is_nan()])

        assert [issue["type"] for issue in issues] == ["NaN_RESULT"]
        assert issues[0]["model"] is not None

    def test_check_operation_does_not_report_definite_issue_on_solver_unknown(self) -> None:
        analyzer = FloatAnalyzer()
        result = AdvancedSymbolicFloat("unknown_float_result")
        numerator = AdvancedSymbolicFloat("unknown_float_numerator")
        denominator = AdvancedSymbolicFloat("unknown_float_denominator")
        solver = IncrementalSolver(timeout_ms=1000)
        solver.set_deadline(time.perf_counter() - 1.0)
        token = active_incremental_solver.set(solver)
        try:
            issues = analyzer.check_operation("/", result, [numerator, denominator], [])
        finally:
            active_incremental_solver.reset(token)

        assert issues == []
        assert analyzer.get_all_issues() == []

    def test_check_comparison(self) -> None:
        analyzer = FloatAnalyzer()
        left = AdvancedSymbolicFloat("l")
        right = AdvancedSymbolicFloat("r")
        issues = analyzer.check_comparison(left, right, [])
        assert isinstance(issues, list)

    def test_check_comparison_records_model_backed_issues(self) -> None:
        analyzer = FloatAnalyzer()
        left = AdvancedSymbolicFloat("nan_comparison_left")
        right = AdvancedSymbolicFloat("nan_comparison_right")

        issues = analyzer.check_comparison(left, right, [left.is_nan()])

        assert [issue["type"] for issue in issues] == ["NAN_COMPARISON"]
        assert issues[0]["model"] is not None
        assert analyzer.get_all_issues() == issues

    def test_check_comparison_does_not_report_definite_issue_on_solver_unknown(self) -> None:
        analyzer = FloatAnalyzer()
        left = AdvancedSymbolicFloat("unknown_comparison_left")
        right = AdvancedSymbolicFloat("unknown_comparison_right")
        solver = IncrementalSolver(timeout_ms=1000)
        solver.set_deadline(time.perf_counter() - 1.0)
        token = active_incremental_solver.set(solver)
        try:
            issues = analyzer.check_comparison(left, right, [])
        finally:
            active_incremental_solver.reset(token)

        assert issues == []
        assert analyzer.get_all_issues() == []

    def test_get_all_issues(self) -> None:
        analyzer = FloatAnalyzer()
        assert analyzer.get_all_issues() == []


class TestAccuracyAnalyzer:
    def test_ulp_difference(self) -> None:
        analyzer = AccuracyAnalyzer()
        a = AdvancedSymbolicFloat("a")
        b = AdvancedSymbolicFloat("b")
        assert z3.is_fp(analyzer.ulp_difference(a, b))

    def test_relative_error(self) -> None:
        analyzer = AccuracyAnalyzer()
        a = AdvancedSymbolicFloat("a")
        b = AdvancedSymbolicFloat("b")
        assert isinstance(analyzer.relative_error(a, b), AdvancedSymbolicFloat)

    def test_check_catastrophic_cancellation(self) -> None:
        analyzer = AccuracyAnalyzer()
        a = AdvancedSymbolicFloat("a")
        b = AdvancedSymbolicFloat("b")
        result = AdvancedSymbolicFloat("r")
        assert isinstance(analyzer.check_catastrophic_cancellation(a, b, result, []), bool)

    def test_check_catastrophic_cancellation_result_returns_model_backed_sat(self) -> None:
        analyzer = AccuracyAnalyzer()
        a = AdvancedSymbolicFloat("cancel_sat_a")
        b = AdvancedSymbolicFloat("cancel_sat_b")
        result_float = AdvancedSymbolicFloat("cancel_sat_r")
        sort = get_fp_sort(FloatPrecision.DOUBLE)

        result = analyzer.check_catastrophic_cancellation_result(
            a,
            b,
            result_float,
            [
                a.z3_expr == z3.FPVal(1.0, sort),
                b.z3_expr == z3.FPVal(-1.0, sort),
                result_float.z3_expr == z3.FPVal(0.0, sort),
            ],
        )

        assert result.is_sat
        assert result.model is not None

    def test_check_catastrophic_cancellation_is_false_on_solver_unknown(self) -> None:
        analyzer = AccuracyAnalyzer()
        a = AdvancedSymbolicFloat("unknown_cancel_a")
        b = AdvancedSymbolicFloat("unknown_cancel_b")
        result = AdvancedSymbolicFloat("unknown_cancel_r")
        solver = IncrementalSolver(timeout_ms=1000)
        solver.set_deadline(time.perf_counter() - 1.0)
        token = active_incremental_solver.set(solver)
        try:
            detected = analyzer.check_catastrophic_cancellation(a, b, result, [])
        finally:
            active_incremental_solver.reset(token)

        assert detected is False

    def test_check_catastrophic_cancellation_result_preserves_solver_unknown(self) -> None:
        analyzer = AccuracyAnalyzer()
        a = AdvancedSymbolicFloat("unknown_cancel_result_a")
        b = AdvancedSymbolicFloat("unknown_cancel_result_b")
        result_float = AdvancedSymbolicFloat("unknown_cancel_result_r")
        solver = IncrementalSolver(timeout_ms=1000)
        solver.set_deadline(time.perf_counter() - 1.0)
        token = active_incremental_solver.set(solver)
        try:
            result = analyzer.check_catastrophic_cancellation_result(a, b, result_float, [])
        finally:
            active_incremental_solver.reset(token)

        assert result.is_unknown
        assert result.model is None
