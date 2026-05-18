"""Tests for pysymex.core.solver.learner module."""

from __future__ import annotations

import pytest
import z3

from pysymex.core.solver.learner import (
    ConflictLearner,
    ConflictWorker,
)


class TestConflictLearner:
    def test_extract_conflict_sync_returns_none_on_empty(self) -> None:
        learner = ConflictLearner()
        constraints: list[z3.BoolRef] = []
        result = learner.extract_conflict_sync(constraints)
        assert result is None

    def test_extract_conflict_sync_returns_none_on_sat(self) -> None:
        learner = ConflictLearner()
        x = z3.Bool("x")
        constraints: list[z3.BoolRef] = [x, z3.BoolVal(True)]
        result = learner.extract_conflict_sync(constraints)
        assert result is None

    def test_extract_conflict_sync_returns_core_indices_on_unsat(self) -> None:
        learner = ConflictLearner()
        x = z3.Bool("x")
        constraints: list[z3.BoolRef] = [x, z3.Not(x)]
        result = learner.extract_conflict_sync(constraints)
        assert result is not None
        assert set(result) == {0, 1}

    def test_extract_conflict_sync_caches_only_validated_cores(self) -> None:
        learner = ConflictLearner()
        x = z3.Bool("x_cached_core")
        constraints: list[z3.BoolRef] = [x, z3.Not(x)]

        first = learner.extract_conflict_sync(constraints)
        second = learner.extract_conflict_sync(constraints)

        assert first is not None
        assert second == first
        assert learner.validated_core_cache_size == 1

    def test_extract_conflict_sync_does_not_cache_sat_constraints(self) -> None:
        learner = ConflictLearner()
        x = z3.Bool("x_sat_no_cache")

        result = learner.extract_conflict_sync([x])

        assert result is None
        assert learner.validated_core_cache_size == 0

    def test_extract_conflict_sync_rejects_unvalidated_core(self) -> None:
        class RejectingLearner(ConflictLearner):
            def _validate_core(
                self, constraints: list[z3.BoolRef], core_indices: list[int]
            ) -> bool:
                _ = constraints, core_indices
                return False

        learner = RejectingLearner()
        x = z3.Bool("x_rejected_core")

        result = learner.extract_conflict_sync([x, z3.Not(x)])

        assert result is None
        assert learner.validated_core_cache_size == 0


class TestConflictWorker:
    def test_dispatch_ignores_over_max_depth(self) -> None:
        learner = ConflictLearner()
        worker = ConflictWorker(learner)
        called = False

        def callback(res: list[int] | None) -> None:
            nonlocal called
            called = True

        constraints: list[z3.BoolRef] = []
        worker.dispatch(constraints, callback, current_depth=10, max_depth=5)
        assert called is False

    def test_dispatch_invokes_callback_with_result(self) -> None:
        learner = ConflictLearner()
        worker = ConflictWorker(learner)
        received_result: list[int] | None = []

        def callback(res: list[int] | None) -> None:
            nonlocal received_result
            received_result = res

        constraints: list[z3.BoolRef] = []
        worker.dispatch(constraints, callback, current_depth=0, max_depth=5)
        assert received_result is None

    def test_dispatch_handles_solver_exception_gracefully(self) -> None:
        class FaultyLearner(ConflictLearner):
            def extract_conflict_sync(self, constraints: list[z3.BoolRef]) -> list[int] | None:
                _ = constraints
                raise z3.Z3Exception("simulated solver error")

        learner = FaultyLearner()
        worker = ConflictWorker(learner)
        received_result: list[int] | None = [1]

        def callback(res: list[int] | None) -> None:
            nonlocal received_result
            received_result = res

        constraints: list[z3.BoolRef] = []
        worker.dispatch(constraints, callback, current_depth=0, max_depth=5)
        assert received_result is None

    def test_dispatch_does_not_swallow_unexpected_exception(self) -> None:
        class FaultyLearner(ConflictLearner):
            def extract_conflict_sync(self, constraints: list[z3.BoolRef]) -> list[int] | None:
                _ = constraints
                raise RuntimeError("simulated error")

        learner = FaultyLearner()
        worker = ConflictWorker(learner)

        def callback(res: list[int] | None) -> None:
            _ = res

        with pytest.raises(RuntimeError, match="simulated error"):
            worker.dispatch([], callback, current_depth=0, max_depth=5)

    def test_wait_all_completes(self) -> None:
        learner = ConflictLearner()
        worker = ConflictWorker(learner)
        result = worker.wait_all()
        assert result is None
