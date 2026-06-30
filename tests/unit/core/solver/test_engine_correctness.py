"""Validation tests that check solver wrapper behavior against raw Z3 semantics."""

from __future__ import annotations

import time
from typing import cast

import pytest
import z3

import pysymex._internal.core.solver.engine.cache.unsat.subset.methods as unsat_subset_methods
from pysymex._internal.core.solver.constraints.hashing import ConstraintHasher
from pysymex._internal.core.solver.engine.incremental import IncrementalSolver
from pysymex._internal.core.solver.engine.policies import path_may_be_feasible
from pysymex._internal.core.solver.engine.results import SolverResult
from tests.unit.core.solver.engine_solver_helpers import is_sat_with_z3


class TestConstraintSolverCorrectnessValidation:
    """Validation tests that check solver wrapper behavior against raw Z3 semantics."""

    def test_check_preserves_solver_exception_as_unknown(self) -> None:
        """Low-level solver check failures remain explicit UNKNOWN results."""

        class _FailingSolver:
            def set(self, *_args: object) -> None:
                return None

            def check(self, *_args: object) -> object:
                raise z3.Z3Exception("simulated check failure")

        solver = IncrementalSolver(use_cache=False)
        solver.solver = cast("z3.Solver", _FailingSolver())

        result = solver.check()

        assert (result.is_unknown, result.is_sat, result.is_unsat) == (True, False, False)

    def test_check_preserves_model_extraction_exception_as_unknown(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SAT checks requiring a model must not surface model extraction failures."""
        solver = IncrementalSolver(use_cache=False)
        x = z3.Int("x_model_extraction_failure")
        solver.add(x > 0)

        def raising_model(self: z3.Solver) -> z3.ModelRef:
            _ = self
            raise z3.Z3Exception("simulated model extraction failure")

        monkeypatch.setattr(z3.Solver, "model", raising_model)

        result = solver.check(need_model=True)

        assert (result.is_unknown, result.is_sat, result.is_unsat) == (True, False, False)
        assert result.model is None

    def test_is_sat_matches_raw_z3_for_sat_case(self) -> None:
        """Check that IncrementalSolver.is_sat returns True on a known SAT system."""
        x = z3.Int("x_sat_case")
        constraints = [x > 2, x < 5]
        solver = IncrementalSolver()
        assert solver.path_may_be_feasible(constraints) == is_sat_with_z3(constraints)

    def test_is_sat_matches_raw_z3_for_unsat_case(self) -> None:
        """Check that IncrementalSolver.is_sat returns False on a known UNSAT system."""
        x = z3.Int("x_unsat_case")
        constraints = [x > 2, x < 0]
        solver = IncrementalSolver()
        assert solver.path_may_be_feasible(constraints) == is_sat_with_z3(constraints)

    def test_check_assumptions_are_not_persisted(self) -> None:
        """Check that assumptions passed to check() do not mutate persistent solver state."""
        x = z3.Int("x_assumption")
        solver = IncrementalSolver()
        solver.add(x > 0)
        first = solver.check(x < 0)
        second = solver.check()
        assert (first.is_unsat, second.is_sat) == (True, True)

    def test_push_pop_preserves_outer_context_soundness(self) -> None:
        """Check push/pop restores outer satisfiability after an UNSAT inner scope."""
        x = z3.Int("x_scope")
        solver = IncrementalSolver()
        solver.add(x >= 1)
        solver.push()
        solver.add(x < 0)
        inner = solver.check()
        solver.pop()
        outer = solver.check()
        assert (inner.is_unsat, outer.is_sat) == (True, True)

    def test_check_cache_reuses_identical_asserted_context(self) -> None:
        """Repeated low-level checks over the same asserted context should hit cache."""
        x = z3.Int("x_check_cache_hit")
        solver = IncrementalSolver(use_cache=True)
        results: list[SolverResult] = []
        for _ in range(3):
            solver.push()
            try:
                solver.add(x > 0)
                results.append(solver.check())
            finally:
                solver.pop()

        stats = solver.get_stats()
        assert [result.is_sat for result in results] == [True, True, True]
        assert stats["cache_hits"] == 2

    def test_check_cache_distinguishes_asserted_contexts(self) -> None:
        """A SAT result for one pushed context must not satisfy a later UNSAT context."""
        x = z3.Int("x_check_cache_context")
        solver = IncrementalSolver(use_cache=True)
        solver.push()
        try:
            solver.add(x > 0)
            first = solver.check()
        finally:
            solver.pop()

        solver.push()
        try:
            solver.add(x > 0, x < 0)
            second = solver.check()
        finally:
            solver.pop()

        stats = solver.get_stats()
        assert first.is_sat and second.is_unsat
        assert stats["cache_hits"] == 0

    def test_check_cache_respects_disabled_cache_flag(self) -> None:
        """Low-level check caching must honor use_cache=False."""
        x = z3.Int("x_check_cache_disabled")
        solver = IncrementalSolver(use_cache=False)
        for _ in range(2):
            solver.push()
            try:
                solver.add(x > 0)
                assert solver.check().is_sat
            finally:
                solver.pop()

        stats = solver.get_stats()
        assert stats["cache_hits"] == 0

    def test_supported_linear_sat_query_uses_z3(self) -> None:
        """Supported integer-linear SAT constraints still go through Z3."""
        x, y = z3.Ints("x_linear_z3 y_linear_z3")
        solver = IncrementalSolver(use_cache=False)

        solver.add(x >= 3, y >= x + 2, x + y < 20)
        result = solver.check()

        assert result.is_sat
        solver_time_ms = solver.get_stats()["solver_time_ms"]
        assert isinstance(solver_time_ms, float)
        assert solver_time_ms > 0.0

    def test_supported_linear_unsat_query_uses_z3(self) -> None:
        """Contradictory supported constraints are decided by Z3."""
        x = z3.Int("x_linear_unsat")
        solver = IncrementalSolver(use_cache=False)

        solver.add(x > 10, x < 0)
        result = solver.check()

        assert result.is_unsat
        solver_time_ms = solver.get_stats()["solver_time_ms"]
        assert isinstance(solver_time_ms, float)
        assert solver_time_ms > 0.0

    def test_linear_model_query_uses_z3_model(self) -> None:
        """Model-producing linear queries return a Z3 model."""
        x = z3.Int("x_linear_model")
        solver = IncrementalSolver(use_cache=False)

        solver.add(x > 0)
        result = solver.check(need_model=True)

        assert result.is_sat
        assert result.model is not None

    def test_check_sat_cached_model_satisfies_constraint(self) -> None:
        """Check SAT results include a model that satisfies constraints."""
        x = z3.Int("x_model")
        solver = IncrementalSolver()
        result = solver.check_sat_cached([x == 9])
        model_value = (
            result.model.eval(x, model_completion=True) if result.model is not None else None
        )
        assert (result.is_sat, model_value) == (True, z3.IntVal(9))

    def test_check_sat_cached_reuses_constraint_fingerprint_without_sexpr(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Cached discriminator fingerprints avoid repeated Z3 string rendering."""
        x = z3.Int("x_cached_fingerprint")
        constraint = x == 6
        solver = IncrementalSolver(warm_start=False)

        first = solver.check_sat_cached([constraint])
        assert first.is_sat

        original_sexpr = z3.ExprRef.sexpr
        sexpr_calls = 0

        def counted_sexpr(expr: z3.ExprRef) -> str:
            nonlocal sexpr_calls
            sexpr_calls += 1
            return original_sexpr(expr)

        monkeypatch.setattr(z3.ExprRef, "sexpr", counted_sexpr)

        second = solver.check_sat_cached([constraint])

        assert second.is_sat
        assert sexpr_calls == 0

    def test_check_sat_cached_drops_literal_true_before_cache_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Literal ``True`` constraints must not fragment cached model queries."""
        x = z3.Int("x_cached_true_literal")
        solver = IncrementalSolver(warm_start=False)
        solver_add = solver.solver.add

        def checked_solver_add(*constraints: z3.BoolRef | list[z3.BoolRef]) -> None:
            flat_constraints: list[z3.BoolRef] = []
            for constraint in constraints:
                if isinstance(constraint, list):
                    flat_constraints.extend(constraint)
                else:
                    flat_constraints.append(constraint)
            assert all(not z3.is_true(constraint) for constraint in flat_constraints)
            solver_add(*constraints)

        monkeypatch.setattr(solver.solver, "add", checked_solver_add)

        result = solver.check_sat_cached([z3.BoolVal(True), x == 4])

        assert result.is_sat
        assert result.model is not None
        assert result.model.eval(x, model_completion=True) == z3.IntVal(4)

    def test_check_sat_cached_short_circuits_literal_false_without_query(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Literal ``False`` is definitive UNSAT and must not reach Z3."""
        x = z3.Int("x_cached_false_literal")
        solver = IncrementalSolver()

        def fail_check(*_assumptions: z3.BoolRef) -> z3.CheckSatResult:
            raise AssertionError("literal False should not query Z3")

        monkeypatch.setattr(solver.solver, "check", fail_check)

        result = solver.check_sat_cached([x == 4, z3.BoolVal(False)])

        assert result.is_unsat
        assert solver.get_stats()["queries"] == 0

    def test_check_sat_cached_reuses_satisfying_warm_model_without_query(self) -> None:
        """A retained model may answer a later model query only if it satisfies all constraints."""
        x = z3.Int("x_warm_model")
        solver = IncrementalSolver()

        first = solver.check_sat_cached([x == 2])
        first_query_count = solver.get_stats()["queries"]
        second = solver.check_sat_cached([x == 2, x >= 0])
        second_query_count = solver.get_stats()["queries"]
        third = solver.check_sat_cached([x == 3])
        third_query_count = solver.get_stats()["queries"]

        assert first.is_sat and first.model is not None
        assert second.is_sat and second.model is first.model
        assert first_query_count == second_query_count == 1
        assert third.is_sat and third.model is not None
        assert third_query_count == 2

    def test_check_sat_result_reuses_unsat_subset_without_query(self) -> None:
        """A cached UNSAT conjunction is enough to reject later supersets."""
        x = z3.Int("x_unsat_subset")
        y = z3.Int("y_unsat_subset")
        total = x + y
        solver = IncrementalSolver()

        first = solver.check_sat_result([total > 0, total < 0])
        first_query_count = solver.get_stats()["queries"]
        second = solver.check_sat_result([y == 1, total > 0, total < 0])
        second_query_count = solver.get_stats()["queries"]

        assert first.is_unsat and second.is_unsat
        assert first_query_count == second_query_count == 1
        assert solver.get_stats()["unsat_subset_cache_size"] == 1

    @pytest.mark.parametrize(
        "constraint",
        [
            z3.Int("x_high_level_sat_cache_int") + z3.Int("y_high_level_sat_cache_int") > 0,
            z3.BitVec("x_high_level_sat_cache_bv", 32) == z3.BitVecVal(7, 32),
        ],
    )
    def test_check_sat_result_reuses_first_high_level_cache_entry(
        self,
        constraint: z3.BoolRef,
    ) -> None:
        """The first cached SAT result should be reusable without a second Z3 check."""
        solver = IncrementalSolver()
        calls = 0
        real_check = solver.solver.check

        def counted_check(*assumptions: z3.BoolRef) -> z3.CheckSatResult:
            nonlocal calls
            calls += 1
            return real_check(*assumptions)

        solver.solver.check = counted_check

        first = solver.check_sat_result([constraint])
        second = solver.check_sat_result([constraint])

        assert first.is_sat and second.is_sat
        assert calls == 1
        assert solver.get_stats()["queries"] == 1
        assert solver.get_stats()["cache_hits"] == 1
        assert solver.get_stats()["cache_size"] == 1

    def test_check_sat_result_unsat_subset_cache_validates_hash_collisions(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """UNSAT subset reuse must validate exact expressions after hash prefiltering."""
        x = z3.Int("x_unsat_subset_collision")
        y = z3.Int("y_unsat_subset_collision")
        z = z3.Int("z_unsat_subset_collision")
        total = x + y

        def forced_hash(self: ConstraintHasher, expr: z3.ExprRef) -> int:
            _ = self
            _ = expr
            return 1

        monkeypatch.setattr(ConstraintHasher, "hash_expr", forced_hash)
        solver = IncrementalSolver()

        first = solver.check_sat_result([total > 0, total < 0])
        first_query_count = solver.get_stats()["queries"]
        second = solver.check_sat_result([y + z > 0])
        second_query_count = solver.get_stats()["queries"]

        assert first.is_unsat
        assert second.is_sat
        assert first_query_count == 1
        assert second_query_count == 2

    def test_unsat_subset_cache_hash_count_prefilter_skips_exact_match(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Hash counts should reject impossible subset matches before exact Z3 equality."""
        x = z3.Int("x_unsat_subset_prefilter")
        y = z3.Int("y_unsat_subset_prefilter")
        z = z3.Int("z_unsat_subset_prefilter")
        total = x + y
        solver = IncrementalSolver()

        first = solver.check_sat_result([total > 0, total < 0])
        first_query_count = solver.get_stats()["queries"]

        def fail_exact_match(
            subset: tuple[z3.BoolRef, ...],
            subset_hashes: tuple[int, ...],
            query_buckets: dict[int, list[z3.BoolRef]],
        ) -> bool:
            _ = subset
            _ = subset_hashes
            _ = query_buckets
            raise AssertionError("exact UNSAT subset matching should be hash-prefiltered")

        monkeypatch.setattr(unsat_subset_methods, "unsat_subset_matches", fail_exact_match)
        second = solver.check_sat_result([y + z > 0])
        second_query_count = solver.get_stats()["queries"]

        assert first.is_unsat
        assert second.is_sat
        assert first_query_count == 1
        assert second_query_count == 2

    def test_check_sat_cached_skips_discriminator_on_cold_unknown(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Cold UNKNOWN model queries must not build a cache discriminator they cannot store."""
        x = z3.Int("x_cached_unknown_no_discriminator")
        solver = IncrementalSolver()

        def unknown_check(*assumptions: z3.BoolRef) -> z3.CheckSatResult:
            _ = assumptions
            return z3.unknown

        def raise_discriminator(_constraints: list[z3.BoolRef]) -> tuple[str, ...]:
            raise AssertionError("discriminator should not be built for a cold UNKNOWN miss")

        monkeypatch.setattr(solver.solver, "check", unknown_check)
        monkeypatch.setattr(solver, "_constraints_discriminator", raise_discriminator)

        result = solver.check_sat_cached([x > 0])

        assert result.is_unknown

    def test_check_sat_result_translates_cross_context_constraints(self) -> None:
        """Cross-context BoolRefs should be translated into the solver context before checking."""
        ctx = z3.Context()
        x = z3.Int("x_cross_context_check", ctx=ctx)
        constraints = [x > 0, x < 3]
        solver = IncrementalSolver()

        first = solver.check_sat_result(constraints)
        second = solver.check_sat_result(constraints)

        stats = solver.get_stats()
        misses = stats["z3_ast_cache_misses"]
        hits = stats["z3_ast_cache_hits"]
        assert first.is_sat and second.is_sat
        assert isinstance(misses, int)
        assert isinstance(hits, int)
        assert misses >= 2
        assert hits >= 2

    def test_get_model_returns_none_for_unsat_constraints(self) -> None:
        """Check that get_model returns None for contradictory constraints."""
        x = z3.Int("x_no_model")
        solver = IncrementalSolver()
        assert solver.get_model([x > 5, x < 0]) is None

    def test_top_level_is_satisfiable_matches_raw_z3_unsat(self) -> None:
        """Check top-level path_may_be_feasible API against raw Z3 on an UNSAT system."""
        x = z3.Int("x_top_unsat")
        constraints = [x >= 1, x <= 0]
        assert path_may_be_feasible(constraints) == is_sat_with_z3(constraints)

    def test_check_sat_result_preserves_deadline_unknown(self) -> None:
        """Detector-facing SAT API must expose deadline exhaustion as UNKNOWN."""
        x = z3.Int("x_deadline_unknown")
        solver = IncrementalSolver(timeout_ms=1000)
        solver.set_deadline(time.perf_counter() - 1.0)

        result = solver.check_sat_result([x > 0])

        assert (result.is_unknown, result.is_sat, result.is_unsat) == (True, False, False)

    def test_check_sat_result_preserves_deadline_unknown_before_literal_shortcut(self) -> None:
        """Expired deadlines dominate exact literal shortcuts for conservative reporting."""
        solver = IncrementalSolver(timeout_ms=1000)
        solver.set_deadline(time.perf_counter() - 1.0)

        result = solver.check_sat_result([z3.BoolVal(True)])

        assert (result.is_unknown, result.is_sat, result.is_unsat) == (True, False, False)

    def test_check_sat_result_rechecks_exact_unknown_without_definitive_cache(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Duplicate inconclusive checks must not become reusable SAT/UNSAT evidence."""
        x = z3.Int("x_reused_unknown")
        y = z3.Int("y_reused_unknown")
        constraint = x + y > 0
        solver = IncrementalSolver(timeout_ms=1000)
        calls = 0

        def unknown_check(*assumptions: z3.BoolRef, need_model: bool = False) -> SolverResult:
            nonlocal calls
            _ = assumptions
            _ = need_model
            calls += 1
            return SolverResult.unknown()

        monkeypatch.setattr(solver, "check", unknown_check)

        first = solver.check_sat_result([constraint])
        second = solver.check_sat_result([constraint])

        assert first.is_unknown
        assert second.is_unknown
        assert calls == 2
        assert solver.cache == {}

    def test_check_sat_result_clears_unknown_memo_on_deadline_change(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Changing solver deadline must allow a formerly UNKNOWN query to run again."""
        x = z3.Int("x_unknown_deadline_clear")
        y = z3.Int("y_unknown_deadline_clear")
        constraint = x + y > 0
        solver = IncrementalSolver(timeout_ms=1000)
        calls = 0

        def staged_check(*assumptions: z3.BoolRef, need_model: bool = False) -> SolverResult:
            nonlocal calls
            _ = assumptions
            _ = need_model
            calls += 1
            if calls == 1:
                return SolverResult.unknown()
            return SolverResult.sat(None)

        monkeypatch.setattr(solver, "check", staged_check)

        first = solver.check_sat_result([constraint])
        solver.set_deadline(None)
        second = solver.check_sat_result([constraint])

        assert first.is_unknown
        assert second.is_sat
        assert calls == 2

    def test_check_sat_result_preserves_canceled_check_as_unknown(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Z3 cancellation during suffix checks must not become an internal engine error."""
        x = z3.Int("x_check_canceled_unknown")
        y = z3.Int("y_check_canceled_unknown")
        solver = IncrementalSolver(timeout_ms=1000)

        def raise_canceled(*_assumptions: z3.BoolRef) -> z3.CheckSatResult:
            raise z3.Z3Exception("check canceled")

        monkeypatch.setattr(solver.solver, "check", raise_canceled)

        result = solver.check_sat_result([x + y > 0])

        assert (result.is_unknown, result.is_sat, result.is_unsat) == (True, False, False)

    def test_check_sat_result_preserves_canceled_sync_path_as_unknown(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Z3 cancellation while synchronizing a known prefix must remain UNKNOWN."""
        x = z3.Int("x_sync_push_canceled_unknown")
        solver = IncrementalSolver(timeout_ms=1000)

        def raise_canceled() -> None:
            raise z3.Z3Exception("push canceled")

        monkeypatch.setattr(solver.solver, "push", raise_canceled)

        result = solver.check_sat_result([x > 0, x < 10], known_sat_prefix_len=1)

        assert (result.is_unknown, result.is_sat, result.is_unsat) == (True, False, False)

    def test_check_sat_result_preserves_runtime_sync_path_add_failure_as_unknown(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Runtime failures during prefix synchronization must clean up as UNKNOWN."""
        x = z3.Int("x_sync_add_runtime_unknown")
        solver = IncrementalSolver(timeout_ms=1000)

        def raise_runtime(*constraints: z3.BoolRef) -> None:
            _ = constraints
            raise RuntimeError("simulated sync-path add failure")

        monkeypatch.setattr(solver, "add", raise_runtime)

        result = solver.check_sat_result([x > 0, x < 10], known_sat_prefix_len=1)

        assert (result.is_unknown, result.is_sat, result.is_unsat) == (True, False, False)
        assert solver.get_stats()["scope_depth"] == 0
        assert solver.active_path == []

    def test_path_may_be_feasible_preserves_potentially_feasible_unknown_path(self) -> None:
        """Path exploration keeps UNKNOWN branches alive through the optimistic predicate."""
        x = z3.Int("x_unknown_path")
        solver = IncrementalSolver(timeout_ms=1000)
        solver.set_deadline(time.perf_counter() - 1.0)

        assert solver.path_may_be_feasible([x > 0]) is True

    def test_check_sat_result_reports_malformed_constraint_as_unknown(self) -> None:
        """Malformed constraints must not be silently dropped into a SAT result."""
        solver = IncrementalSolver()
        constraints = cast("list[z3.BoolRef]", [object()])

        result = solver.check_sat_result(constraints)

        assert (result.is_unknown, result.is_sat, result.is_unsat) == (True, False, False)

    def test_check_sat_cached_reports_malformed_constraint_as_unknown(self) -> None:
        """Model-producing cached SAT checks must preserve malformed input as UNKNOWN."""
        solver = IncrementalSolver()
        constraints = cast("list[z3.BoolRef]", [object()])

        result = solver.check_sat_cached(constraints)

        assert (result.is_unknown, result.is_sat, result.is_unsat) == (True, False, False)

    def test_check_sat_cached_runtime_scope_cleanup_failure_resets(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Cached-query cleanup failure must reset the solver before returning UNKNOWN."""
        x = z3.Int("x_cached_runtime_pop_failure")
        solver = IncrementalSolver()

        def raise_runtime() -> None:
            raise RuntimeError("simulated cached-query pop failure")

        monkeypatch.setattr(solver.solver, "pop", raise_runtime)

        result = solver.check_sat_cached([x > 0])

        assert (result.is_unknown, result.is_sat, result.is_unsat) == (True, False, False)
        assert solver.get_stats()["scope_depth"] == 0
        assert solver.check().is_sat

    def test_path_may_be_feasible_keeps_malformed_constraint_path_alive(self) -> None:
        """The optimistic predicate keeps UNKNOWN malformed paths alive for exploration."""
        solver = IncrementalSolver()
        constraints = cast("list[z3.BoolRef]", [object()])

        assert solver.path_may_be_feasible(constraints) is True
