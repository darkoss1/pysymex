import time

import pytest
import z3

import pysymex.core.solver.engine as mod


def _is_sat_with_z3(constraints: list[z3.BoolRef]) -> bool:
    """Return whether the given constraints are satisfiable in raw Z3."""
    solver = z3.Solver()
    solver.add(constraints)
    return solver.check() == z3.sat


def _is_unsat_with_z3(constraints: list[z3.BoolRef]) -> bool:
    """Return whether the given constraints are unsatisfiable in raw Z3."""
    solver = z3.Solver()
    solver.add(constraints)
    return solver.check() == z3.unsat


class TestSolverResult:
    def test_sat(self) -> None:
        result = mod.SolverResult.sat(None)
        assert result.is_sat and not result.is_unsat

    def test_unsat(self) -> None:
        result = mod.SolverResult.unsat()
        assert result.is_unsat and not result.is_sat

    def test_unknown(self) -> None:
        result = mod.SolverResult.unknown()
        assert result.is_unknown


class TestIncrementalSolver:
    def test_reset(self) -> None:
        solver = mod.IncrementalSolver()
        solver.push()
        solver.reset()
        assert solver.get_stats()["scope_depth"] == 0

    def test_constraint_optimizer(self) -> None:
        solver = mod.IncrementalSolver()
        assert solver.constraint_optimizer() is not None

    def test_push(self) -> None:
        solver = mod.IncrementalSolver()
        solver.push()
        assert solver.get_stats()["scope_depth"] == 1

    def test_pop(self) -> None:
        solver = mod.IncrementalSolver()
        solver.push()
        solver.pop()
        assert solver.get_stats()["scope_depth"] == 0

    def test_add(self) -> None:
        solver = mod.IncrementalSolver()
        solver.add(z3.Bool("a"))
        assert solver.get_stats()["queries"] == 0

    def test_enter_scope(self) -> None:
        solver = mod.IncrementalSolver()
        solver.enter_scope([z3.Bool("a")])
        assert solver.get_stats()["scope_depth"] == 1

    def test_leave_scope(self) -> None:
        solver = mod.IncrementalSolver()
        solver.enter_scope([])
        solver.leave_scope()
        assert solver.get_stats()["scope_depth"] == 0

    def test_check(self) -> None:
        solver = mod.IncrementalSolver()
        result = solver.check()
        assert result.is_sat

    def test_check_flushes_pending_constraints_into_solver_scope(self) -> None:
        solver = mod.IncrementalSolver()
        x = z3.Int("x_flush_pending")

        solver.push()
        solver.add(x > 0)
        result = solver.check(x < 0)

        assert result.is_unsat
        assert solver._pending_constraint_scope_stack[-1] == []  # type: ignore[reportPrivateUsage]
        solver.pop()
        assert solver.check().is_sat

    def test_is_sat(self) -> None:
        solver = mod.IncrementalSolver()
        x = z3.Int("x")
        assert solver.is_sat([x > 0])

    def test_check_sat_cached(self) -> None:
        solver = mod.IncrementalSolver()
        x = z3.Int("x")
        result = solver.check_sat_cached([x > 0])
        assert result.is_sat

    def test_check_sat_cached_preserves_canceled_push_as_unknown(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Model-producing cached checks must not surface Z3 cancellation as an engine error."""
        solver = mod.IncrementalSolver()
        x = z3.Int("x_cached_push_canceled")

        def raise_canceled() -> None:
            raise z3.Z3Exception("push canceled")

        monkeypatch.setattr(solver._solver, "push", raise_canceled)  # type: ignore[reportPrivateUsage]

        result = solver.check_sat_cached([x > 0])

        assert (result.is_unknown, result.is_sat, result.is_unsat) == (True, False, False)

    def test_get_model(self) -> None:
        solver = mod.IncrementalSolver()
        x = z3.Int("x")
        model = solver.get_model([x == 2])
        assert model is not None

    def test_get_model_string(self) -> None:
        solver = mod.IncrementalSolver()
        x = z3.Int("x")
        model_str = solver.get_model_string([x == 2])
        assert model_str is not None

    def test_extract_counterexample(self) -> None:
        solver = mod.IncrementalSolver()
        x = z3.Int("x")
        data = solver.extract_counterexample([x == 3])
        assert isinstance(data, dict)

    def test_implies(self) -> None:
        solver = mod.IncrementalSolver()
        x = z3.Int("x")
        assert solver.implies(x > 1, x > 0)

    def test_simplify(self) -> None:
        solver = mod.IncrementalSolver()
        x = z3.Int("x")
        simplified = solver.simplify(x + 0)
        assert z3.is_expr(simplified)

    def test_get_unsat_core(self) -> None:
        solver = mod.IncrementalSolver()
        x = z3.Int("x")
        core = solver.get_unsat_core([x > 0, x < 0])
        assert core is not None

    def test_get_stats(self) -> None:
        solver = mod.IncrementalSolver()
        stats = solver.get_stats()
        assert "queries" in stats and "cache_hits" in stats

    def test_z3_ast_translation_cache_reuses_same_context_expression(self) -> None:
        ctx = z3.Context()
        x = z3.Int("x_ast_cache", ctx=ctx)
        constraint = x > 0
        solver = mod.IncrementalSolver()

        solver.add(constraint)
        solver.add(constraint)

        stats = solver.get_stats()
        assert stats["z3_ast_cache_misses"] == 1
        assert stats["z3_ast_cache_hits"] == 1
        assert stats["z3_ast_cache_size"] == 1
        assert solver.check().is_sat

    def test_z3_ast_translation_cache_does_not_reuse_across_source_contexts(self) -> None:
        ctx_a = z3.Context()
        ctx_b = z3.Context()
        constraint_a = z3.Int("x_ast_context", ctx=ctx_a) > 0
        constraint_b = z3.Int("x_ast_context", ctx=ctx_b) > 0
        solver = mod.IncrementalSolver()

        solver.add(constraint_a)
        solver.add(constraint_b)

        stats = solver.get_stats()
        assert stats["z3_ast_cache_misses"] == 2
        assert stats["z3_ast_cache_hits"] == 0
        assert stats["z3_ast_cache_size"] == 2
        assert solver.check().is_sat

    def test_z3_ast_translation_cache_bypasses_main_context_expressions(self) -> None:
        """Main-context BoolRefs are already usable and should not pay signature-cache cost."""
        x = z3.Int("x_ast_main_context")
        constraint = x > 0
        solver = mod.IncrementalSolver()

        solver.add(constraint)
        solver.add(constraint)

        stats = solver.get_stats()
        assert stats["z3_ast_cache_misses"] == 0
        assert stats["z3_ast_cache_hits"] == 0
        assert stats["z3_ast_cache_size"] == 0
        assert solver.check().is_sat

    def test_expr_equal_with_colliding_ids(self) -> None:
        """P1: IncrementalSolver._expr_equal must not treat colliding IDs across contexts as equal."""
        ctx1 = z3.Context()
        ctx2 = z3.Context()
        x1 = z3.Int("x", ctx1) > 0
        x2 = z3.Int("y", ctx2) > 0

        solver = mod.IncrementalSolver()
        assert not solver._expr_equal(x1, x2)  # type: ignore[reportPrivateUsage]


def test_safe_z3_eq_context_soundness() -> None:
    """Check that safe_z3_eq correctly handles cross-context and recycled Z3 AST IDs."""
    from pysymex.core.types.base import safe_z3_eq

    ctx1 = z3.Context()
    ctx2 = z3.Context()
    x1 = z3.Int("x", ctx1) > 0
    x2 = z3.Int("y", ctx2) > 0

    assert safe_z3_eq(x1, x2) is False
    assert safe_z3_eq(x1, x1) is True


def test_create_solver() -> None:
    solver = mod.create_solver()
    assert isinstance(solver, z3.Solver)


def test_is_satisfiable() -> None:
    x = z3.Int("x")
    assert mod.is_satisfiable([x == 1])


def test_get_model() -> None:
    x = z3.Int("x")
    assert mod.get_model([x == 1]) is not None


def test_get_model_uses_active_incremental_solver() -> None:
    x = z3.Int("active_model_x")
    solver = mod.IncrementalSolver()
    token = mod.active_incremental_solver.set(solver)
    try:
        model = mod.get_model([x == 7])
    finally:
        mod.active_incremental_solver.reset(token)

    assert model is not None
    assert solver.get_stats()["queries"] == 1


def test_get_model_string() -> None:
    x = z3.Int("x")
    assert mod.get_model_string([x == 1]) is not None


def test_prove() -> None:
    x = z3.Int("x")
    assert mod.prove(x == x)


def test_clear_solver_caches() -> None:
    mod.clear_solver_caches()
    assert isinstance(mod.DEFAULT_SOLVER_TIMEOUT_MS, int)


class TestConstraintSolverCorrectnessValidation:
    """Validation tests that check solver wrapper behavior against raw Z3 semantics."""

    def test_is_sat_matches_raw_z3_for_sat_case(self) -> None:
        """Check that IncrementalSolver.is_sat returns True on a known SAT system."""
        x = z3.Int("x_sat_case")
        constraints = [x > 2, x < 5]
        solver = mod.IncrementalSolver()
        assert solver.is_sat(constraints) == _is_sat_with_z3(constraints)

    def test_is_sat_matches_raw_z3_for_unsat_case(self) -> None:
        """Check that IncrementalSolver.is_sat returns False on a known UNSAT system."""
        x = z3.Int("x_unsat_case")
        constraints = [x > 2, x < 0]
        solver = mod.IncrementalSolver()
        assert solver.is_sat(constraints) == _is_sat_with_z3(constraints)

    def test_check_assumptions_are_not_persisted(self) -> None:
        """Check that assumptions passed to check() do not mutate persistent solver state."""
        x = z3.Int("x_assumption")
        solver = mod.IncrementalSolver()
        solver.add(x > 0)
        first = solver.check(x < 0)
        second = solver.check()
        assert (first.is_unsat, second.is_sat) == (True, True)

    def test_push_pop_preserves_outer_context_soundness(self) -> None:
        """Check push/pop restores outer satisfiability after an UNSAT inner scope."""
        x = z3.Int("x_scope")
        solver = mod.IncrementalSolver()
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
        solver = mod.IncrementalSolver(use_cache=True)
        results: list[mod.SolverResult] = []
        for _ in range(3):
            solver.push()
            try:
                solver.add(x > 0)
                results.append(solver.check())
            finally:
                solver.pop()

        stats = solver.get_stats()
        assert [result.is_sat for result in results] == [True, True, True]
        assert stats["cache_hits"] == 1

    def test_check_cache_distinguishes_asserted_contexts(self) -> None:
        """A SAT result for one pushed context must not satisfy a later UNSAT context."""
        x = z3.Int("x_check_cache_context")
        solver = mod.IncrementalSolver(use_cache=True)
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
        solver = mod.IncrementalSolver(use_cache=False)
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
        solver = mod.IncrementalSolver(use_cache=False)

        solver.add(x >= 3, y >= x + 2, x + y < 20)
        result = solver.check()

        assert result.is_sat
        solver_time_ms = solver.get_stats()["solver_time_ms"]
        assert isinstance(solver_time_ms, float)
        assert solver_time_ms > 0.0

    def test_supported_linear_unsat_query_uses_z3(self) -> None:
        """Contradictory supported constraints are decided by Z3."""
        x = z3.Int("x_linear_unsat")
        solver = mod.IncrementalSolver(use_cache=False)

        solver.add(x > 10, x < 0)
        result = solver.check()

        assert result.is_unsat
        solver_time_ms = solver.get_stats()["solver_time_ms"]
        assert isinstance(solver_time_ms, float)
        assert solver_time_ms > 0.0

    def test_linear_model_query_uses_z3_model(self) -> None:
        """Model-producing linear queries return a Z3 model."""
        x = z3.Int("x_linear_model")
        solver = mod.IncrementalSolver(use_cache=False)

        solver.add(x > 0)
        result = solver.check(need_model=True)

        assert result.is_sat
        assert result.model is not None

    def test_check_sat_cached_model_satisfies_constraint(self) -> None:
        """Check SAT results include a model that satisfies constraints."""
        x = z3.Int("x_model")
        solver = mod.IncrementalSolver()
        result = solver.check_sat_cached([x == 9])
        model_value = (
            result.model.eval(x, model_completion=True) if result.model is not None else None
        )
        assert (result.is_sat, model_value) == (True, z3.IntVal(9))

    def test_check_sat_result_translates_cross_context_constraints(self) -> None:
        """Cross-context BoolRefs should be translated into the solver context before checking."""
        ctx = z3.Context()
        x = z3.Int("x_cross_context_check", ctx=ctx)
        constraints = [x > 0, x < 3]
        solver = mod.IncrementalSolver()

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
        solver = mod.IncrementalSolver()
        assert solver.get_model([x > 5, x < 0]) is None

    def test_implies_matches_raw_validity_check(self) -> None:
        """Check implication answers against raw Z3 validity encoding."""
        x = z3.Int("x_implies")
        antecedent = x > 10
        consequent = x > 0
        raw_solver = z3.Solver()
        raw_solver.add(antecedent, z3.Not(consequent))
        expected = raw_solver.check() == z3.unsat
        solver = mod.IncrementalSolver()
        assert solver.implies(antecedent, consequent) == expected

    def test_implies_translates_cross_context_valid_implication(self) -> None:
        """Cross-context BoolRefs should be translated before implication checks."""
        ctx = z3.Context()
        x = z3.Int("x_cross_context_implies_valid", ctx=ctx)
        solver = mod.IncrementalSolver()

        assert solver.implies(x > 1, x > 0) is True

    def test_implies_translates_cross_context_invalid_implication(self) -> None:
        """Cross-context translation must not turn an invalid implication into proof."""
        ctx = z3.Context()
        x = z3.Int("x_cross_context_implies_invalid", ctx=ctx)
        solver = mod.IncrementalSolver()

        assert solver.implies(x > 0, x > 1) is False

    def test_unsat_core_output_is_unsat_subset(self) -> None:
        """Check that returned unsat core remains unsatisfiable under raw Z3."""
        x = z3.Int("x_core")
        y = z3.Int("y_core")
        constraints = [x > 0, x < 0, y == 1]
        solver = mod.IncrementalSolver()
        core = solver.get_unsat_core(constraints)
        core_constraints = core.core if core is not None else []
        assert core is not None and _is_unsat_with_z3(core_constraints)

    def test_unsat_core_translates_cross_context_constraints(self) -> None:
        """UNSAT-core extraction should match SAT checks for cross-context constraints."""
        ctx = z3.Context()
        x = z3.Int("x_cross_context_core", ctx=ctx)
        constraints = [x > 0, x < 0]
        solver = mod.IncrementalSolver()

        result = solver.check_sat_result(constraints)
        core = solver.get_unsat_core(constraints)

        assert result.is_unsat
        assert core is not None
        assert set(core.core_indices) == {0, 1}
        assert _is_unsat_with_z3(core.core)

    def test_top_level_is_satisfiable_matches_raw_z3_unsat(self) -> None:
        """Check top-level is_satisfiable API against raw Z3 on an UNSAT system."""
        x = z3.Int("x_top_unsat")
        constraints = [x >= 1, x <= 0]
        assert mod.is_satisfiable(constraints) == _is_sat_with_z3(constraints)

    def test_check_sat_result_preserves_deadline_unknown(self) -> None:
        """Detector-facing SAT API must expose deadline exhaustion as UNKNOWN."""
        x = z3.Int("x_deadline_unknown")
        solver = mod.IncrementalSolver(timeout_ms=1000)
        solver.set_deadline(time.perf_counter() - 1.0)

        result = solver.check_sat_result([x > 0])

        assert (result.is_unknown, result.is_sat, result.is_unsat) == (True, False, False)

    def test_check_sat_result_preserves_canceled_push_as_unknown(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Z3 cancellation during scoped checks must not become an internal engine error."""
        x = z3.Int("x_push_canceled_unknown")
        solver = mod.IncrementalSolver(timeout_ms=1000)

        def raise_canceled() -> None:
            raise z3.Z3Exception("push canceled")

        monkeypatch.setattr(solver._solver, "push", raise_canceled)  # type: ignore[reportPrivateUsage]

        result = solver.check_sat_result([x > 0])

        assert (result.is_unknown, result.is_sat, result.is_unsat) == (True, False, False)

    def test_check_sat_result_preserves_canceled_sync_path_as_unknown(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Z3 cancellation while synchronizing a known prefix must remain UNKNOWN."""
        x = z3.Int("x_sync_push_canceled_unknown")
        solver = mod.IncrementalSolver(timeout_ms=1000)

        def raise_canceled() -> None:
            raise z3.Z3Exception("push canceled")

        monkeypatch.setattr(solver._solver, "push", raise_canceled)  # type: ignore[reportPrivateUsage]

        result = solver.check_sat_result([x > 0, x < 10], known_sat_prefix_len=1)

        assert (result.is_unknown, result.is_sat, result.is_unsat) == (True, False, False)

    def test_legacy_is_sat_preserves_potentially_feasible_unknown_path(self) -> None:
        """Path exploration keeps UNKNOWN branches alive through the legacy bool API."""
        x = z3.Int("x_legacy_unknown")
        solver = mod.IncrementalSolver(timeout_ms=1000)
        solver.set_deadline(time.perf_counter() - 1.0)

        assert solver.is_sat([x > 0]) is True
