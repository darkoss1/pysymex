import threading

from pytest import MonkeyPatch
import z3

from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.solver.engine.results import SolverResult
from pysymex.core.solver.partitioning import ConstraintPartitioner, ParallelSolver


def test_core_lazy_exports_use_partitioning_owner() -> None:
    """Scenario: top-level core export access; expected solver owner identity."""
    import pysymex.core as core

    assert core.ConstraintPartitioner is ConstraintPartitioner
    assert core.ParallelSolver is ParallelSolver


class _InspectableParallelSolver(ParallelSolver):
    def combine_for_test(self, models: list[z3.ModelRef]) -> SolverResult:
        return self._combine_models(models)


class _UnknownPartitionParallelSolver(ParallelSolver):
    def _solve_partition(self, constraints: list[z3.BoolRef]) -> SolverResult:
        joined = " ".join(str(constraint) for constraint in constraints)
        if "parallel_unknown_partition" in joined:
            return SolverResult.unknown()
        return super()._solve_partition(constraints)


class _ThreadRecordingParallelSolver(ParallelSolver):
    def __init__(self) -> None:
        super().__init__()
        self.solve_thread_ids: set[int] = set()

    def _solve_partition(self, constraints: list[z3.BoolRef]) -> SolverResult:
        self.solve_thread_ids.add(threading.get_ident())
        return super()._solve_partition(constraints)


class TestConstraintPartitioner:
    """Test suite for ConstraintPartitioner."""

    def test_partition(self) -> None:
        """Scenario: independent x/y constraints; expected two partitions."""
        part = ConstraintPartitioner()
        x = z3.Int("x")
        y = z3.Int("y")
        partitions = part.partition([x > 0, y > 0])
        assert len(partitions) == 2


class TestParallelSolver:
    """Test suite for ParallelSolver."""

    def test_check(self) -> None:
        """Scenario: satisfiable constraint set; expected SAT status true."""
        solver = ParallelSolver()
        x = z3.Int("x")
        result = solver.check([x > 0, x < 2])
        assert result.is_sat
        assert result.model is not None

    def test_check_definite_unsat(self) -> None:
        """Scenario: contradictory constraint set; expected definite UNSAT status."""
        solver = ParallelSolver()
        x = z3.Int("parallel_unsat_x")

        result = solver.check([x > 0, x < 0])

        assert result.is_unsat
        assert result.model is None

    def test_check_preserves_unknown_as_possible_sat(self) -> None:
        """Scenario: solver deadline exhausted; expected possible SAT without model."""
        solver = ParallelSolver(timeout_ms=0)
        x = z3.Int("parallel_unknown_x")

        result = solver.check([x > 0])

        assert result.is_unknown
        assert result.model is None

    def test_check_does_not_return_partial_model_when_any_partition_unknown(self) -> None:
        """Scenario: one partition unknown; expected no misleading partial model."""
        solver = _UnknownPartitionParallelSolver()
        known = z3.Int("parallel_known_partition")
        unknown = z3.Int("parallel_unknown_partition")

        result = solver.check([known == 1, unknown > 0])

        assert result.is_unknown
        assert result.model is None

    def test_check_partition_add_failure_returns_unknown(self, monkeypatch: MonkeyPatch) -> None:
        """Scenario: partition solver add fails; expected inconclusive result."""
        solver = ParallelSolver()
        x = z3.Int("parallel_partition_add_failure")

        def raising_add(self: IncrementalSolver, *constraints: z3.BoolRef) -> None:
            _ = self
            _ = constraints
            raise z3.Z3Exception("forced parallel partition add failure")

        monkeypatch.setattr(IncrementalSolver, "add", raising_add)

        result = solver.check([x > 0])

        assert result.is_unknown
        assert result.model is None

    def test_combine_models_treats_inconsistent_selected_models_as_unknown(self) -> None:
        """Scenario: inconsistent selected models; expected inconclusive combination."""
        solver = _InspectableParallelSolver()
        x = z3.Int("parallel_combine_x")
        first = z3.Solver()
        first.add(x == 1)
        assert first.check() == z3.sat
        second = z3.Solver()
        second.add(x == 2)
        assert second.check() == z3.sat

        combined = solver.combine_for_test([first.model(), second.model()])

        assert combined.is_unknown
        assert combined.model is None

    def test_combine_models_add_failure_returns_unknown(self, monkeypatch: MonkeyPatch) -> None:
        """Scenario: model-combination add fails; expected inconclusive result."""
        solver = _InspectableParallelSolver()
        x = z3.Int("parallel_combine_add_failure_x")
        y = z3.Int("parallel_combine_add_failure_y")
        first = z3.Solver()
        first.add(x == 1)
        assert first.check() == z3.sat
        second = z3.Solver()
        second.add(y == 2)
        assert second.check() == z3.sat

        def raising_add(self: IncrementalSolver, *constraints: z3.BoolRef) -> None:
            _ = self
            _ = constraints
            raise z3.Z3Exception("forced parallel combine add failure")

        monkeypatch.setattr(IncrementalSolver, "add", raising_add)

        combined = solver.combine_for_test([first.model(), second.model()])

        assert combined.is_unknown
        assert combined.model is None

    def test_check_solves_partitions_on_calling_thread(self) -> None:
        """Scenario: independent partitions; expected no threaded Z3 solving."""
        solver = _ThreadRecordingParallelSolver()
        x = z3.Int("parallel_serial_x")
        y = z3.Int("parallel_serial_y")
        calling_thread_id = threading.get_ident()

        result = solver.check([x == 1, y == 2])

        assert result.is_sat
        assert result.model is not None
        assert solver.solve_thread_ids == {calling_thread_id}
