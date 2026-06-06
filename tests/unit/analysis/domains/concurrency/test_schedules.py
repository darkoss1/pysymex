import time
from typing import cast

from pytest import MonkeyPatch
import z3

from pysymex.analysis.domains.concurrency import ConcurrencyIssueKind, RaceCheckStatus
from pysymex.analysis.domains.concurrency.analyzer import ConcurrencyAnalyzer
from pysymex.analysis.domains.concurrency.schedules import ScheduleSearchStatus
from pysymex.core.solver.engine.results import SolverResult


class TestConcurrencySchedules:
    """Tests for Z3-backed race and schedule search helpers."""

    def test_check_race_condition_z3(self) -> None:
        analyzer = ConcurrencyAnalyzer()
        ok, issue = analyzer.check_race_condition_z3("x", 42)
        assert ok is True
        assert issue is None

    def test_check_race_condition_z3_result_reports_no_race(self) -> None:
        analyzer = ConcurrencyAnalyzer()

        result = analyzer.check_race_condition_z3_result("x", 42)

        assert result.status == RaceCheckStatus.NOT_FOUND
        assert result.is_safe
        assert result.issue is None
        assert result.reason is None

    def test_check_race_condition_z3_reports_definite_reordering(self) -> None:
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        analyzer.create_thread("t2")
        analyzer.record_write("t1", "x")
        analyzer.record_write("t2", "x")

        ok, issue = analyzer.check_race_condition_z3("x", 42)

        assert ok is False
        assert issue is not None
        assert issue.kind == ConcurrencyIssueKind.RACE_CONDITION
        assert issue.severity == "error"

    def test_check_race_condition_z3_result_reports_definite_reordering(self) -> None:
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        analyzer.create_thread("t2")
        analyzer.record_write("t1", "x")
        analyzer.record_write("t2", "x")

        result = analyzer.check_race_condition_z3_result("x", 42)

        assert result.status == RaceCheckStatus.FOUND
        assert not result.is_safe
        assert result.reason is None
        assert result.issue is not None
        assert result.issue.kind == ConcurrencyIssueKind.RACE_CONDITION
        assert result.issue.severity == "error"

    def test_check_race_condition_z3_reports_solver_unknown_as_inconclusive(self) -> None:
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        analyzer.create_thread("t2")
        analyzer.record_write("t1", "x")
        analyzer.record_write("t2", "x")
        analyzer.solver.set_deadline(time.perf_counter() - 1.0)

        ok, issue = analyzer.check_race_condition_z3("x", 42)

        assert ok is False
        assert issue is not None
        assert issue.kind == ConcurrencyIssueKind.RACE_CONDITION
        assert issue.severity == "warning"
        assert "unknown" in issue.message

    def test_check_race_condition_z3_result_reports_solver_unknown(self) -> None:
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        analyzer.create_thread("t2")
        analyzer.record_write("t1", "x")
        analyzer.record_write("t2", "x")
        analyzer.solver.set_deadline(time.perf_counter() - 1.0)

        result = analyzer.check_race_condition_z3_result("x", 42)

        assert result.status == RaceCheckStatus.INCONCLUSIVE
        assert not result.is_safe
        assert result.reason is not None
        assert "unknown" in result.reason
        assert result.issue is not None
        assert result.issue.kind == ConcurrencyIssueKind.RACE_CONDITION
        assert result.issue.severity == "warning"

    def test_check_race_condition_z3_reports_query_failure_as_inconclusive(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        analyzer.create_thread("t2")
        analyzer.record_write("t1", "x")
        analyzer.record_write("t2", "x")

        def raising_check(*constraints: z3.BoolRef, need_model: bool = False) -> object:
            _ = constraints
            _ = need_model
            raise z3.Z3Exception("forced race query failure")

        monkeypatch.setattr(analyzer.solver, "check", raising_check)

        ok, issue = analyzer.check_race_condition_z3("x", 42)

        assert ok is False
        assert issue is not None
        assert issue.kind == ConcurrencyIssueKind.RACE_CONDITION
        assert issue.severity == "warning"
        assert "unknown" in issue.message
        assert getattr(analyzer.solver, "_scope_depth") == 0

    def test_find_problematic_schedule(self) -> None:
        analyzer = ConcurrencyAnalyzer()
        schedule = analyzer.find_problematic_schedule(z3.BoolVal(True))
        assert schedule is None

    def test_find_problematic_schedule_result_reports_solver_unknown(self) -> None:
        analyzer = ConcurrencyAnalyzer()
        analyzer.solver.set_deadline(time.perf_counter() - 1.0)

        result = analyzer.find_problematic_schedule_result(z3.BoolVal(False))

        assert result.status == ScheduleSearchStatus.INCONCLUSIVE
        assert result.found is False
        assert result.schedule is None
        assert result.reason is not None
        assert "unknown" in result.reason
        assert analyzer.find_problematic_schedule(z3.BoolVal(False)) is None

    def test_find_problematic_schedule_query_failure_is_inconclusive(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        analyzer.record_write("t1", "x")

        def raising_check(*constraints: z3.BoolRef, need_model: bool = False) -> object:
            _ = constraints
            _ = need_model
            raise z3.Z3Exception("forced schedule query failure")

        monkeypatch.setattr(analyzer.solver, "check", raising_check)

        result = analyzer.find_problematic_schedule_result(
            z3.BoolVal(False),
            path_constraints=[z3.Bool("schedule_scope_failure")],
        )

        assert result.status == ScheduleSearchStatus.INCONCLUSIVE
        assert result.schedule is None
        assert result.reason is not None
        assert "unknown" in result.reason
        assert (
            analyzer.find_problematic_schedule(
                z3.BoolVal(False),
                path_constraints=[z3.Bool("schedule_scope_failure_legacy")],
            )
            is None
        )
        assert getattr(analyzer.solver, "_scope_depth") == 0

    def test_find_problematic_schedule_model_evaluation_failure_is_inconclusive(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        analyzer.record_write("t1", "x")

        class _ModelWithFailingEval:
            def eval(
                self,
                expr: z3.ExprRef,
                *,
                model_completion: bool = False,
            ) -> z3.ExprRef:
                _ = expr
                _ = model_completion
                raise z3.Z3Exception("forced schedule model evaluation failure")

        def sat_without_usable_model(_constraints: list[z3.BoolRef]) -> SolverResult:
            model = cast("z3.ModelRef", _ModelWithFailingEval())
            return SolverResult.sat(model)

        monkeypatch.setattr(analyzer.solver, "check_sat_result", sat_without_usable_model)

        result = analyzer.find_problematic_schedule_result(z3.BoolVal(False))

        assert result.status == ScheduleSearchStatus.INCONCLUSIVE
        assert result.schedule is None
        assert result.reason is not None
        assert "model evaluation failed" in result.reason
        assert analyzer.find_problematic_schedule(z3.BoolVal(False)) is None
