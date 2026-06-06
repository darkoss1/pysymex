"""Tests for solver result and incremental solver mechanics."""

from __future__ import annotations

import time

import pytest
import z3

from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.solver.engine.results import SolverResult


class TestSolverResult:
    def test_sat(self) -> None:
        result = SolverResult.sat(None)
        assert result.is_sat and not result.is_unsat

    def test_unsat(self) -> None:
        result = SolverResult.unsat()
        assert result.is_unsat and not result.is_sat

    def test_unknown(self) -> None:
        result = SolverResult.unknown()
        assert result.is_unknown


class TestIncrementalSolver:
    def test_reset(self) -> None:
        solver = IncrementalSolver()
        solver.push()
        solver.reset()
        assert solver.get_stats()["scope_depth"] == 0

    def test_constraint_optimizer(self) -> None:
        solver = IncrementalSolver()
        assert solver.constraint_optimizer() is not None

    def test_push(self) -> None:
        solver = IncrementalSolver()
        solver.push()
        assert solver.get_stats()["scope_depth"] == 1

    def test_pop(self) -> None:
        solver = IncrementalSolver()
        solver.push()
        solver.pop()
        assert solver.get_stats()["scope_depth"] == 0

    def test_add(self) -> None:
        solver = IncrementalSolver()
        solver.add(z3.Bool("a"))
        assert solver.get_stats()["queries"] == 0

    def test_check(self) -> None:
        solver = IncrementalSolver()
        result = solver.check()
        assert result.is_sat

    def test_check_flushes_pending_constraints_into_solver_scope(self) -> None:
        solver = IncrementalSolver()
        x = z3.Int("x_flush_pending")

        solver.push()
        solver.add(x > 0)
        result = solver.check(x < 0)

        assert result.is_unsat
        assert solver.pending_constraint_scope_stack[-1] == []
        solver.pop()
        assert solver.check().is_sat

    def test_is_sat(self) -> None:
        solver = IncrementalSolver()
        x = z3.Int("x")
        assert solver.path_may_be_feasible([x > 0])

    def test_short_known_prefix_skips_independence_slicing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        solver = IncrementalSolver()

        def fail_slice(prefix: list[z3.BoolRef], query: object) -> list[z3.BoolRef]:
            _ = prefix, query
            raise AssertionError("small proven prefixes should not pay slicing overhead")

        monkeypatch.setattr(solver, "_slice_prefix_for_suffix", fail_slice)
        x = z3.Int("x_short_prefix")
        y = z3.Int("y_short_prefix")

        result = solver.check_sat_result(
            [x > 0, y > 0, x < 5],
            known_sat_prefix_len=2,
        )

        assert result.is_sat

    def test_long_known_prefix_still_uses_independence_slicing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        solver = IncrementalSolver()
        calls: list[tuple[int, int]] = []

        def capture_slice(
            prefix: list[z3.BoolRef],
            query: list[z3.BoolRef] | z3.BoolRef,
        ) -> list[z3.BoolRef]:
            suffix = [query] if isinstance(query, z3.BoolRef) else list(query)
            calls.append((len(prefix), len(suffix)))
            return prefix

        monkeypatch.setattr(solver, "_slice_prefix_for_suffix", capture_slice)
        values = [z3.Int(f"x_long_prefix_{index}") for index in range(65)]
        constraints = [value > 0 for value in values[:64]]

        result = solver.check_sat_result(
            [*constraints, values[64] > 0],
            known_sat_prefix_len=64,
        )

        assert result.is_sat
        assert calls == [(64, 1)]

    def test_check_sat_cached(self) -> None:
        solver = IncrementalSolver()
        x = z3.Int("x")
        result = solver.check_sat_cached([x > 0])
        assert result.is_sat

    def test_check_sat_cached_primary_collision_keeps_models_isolated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        solver = IncrementalSolver()

        def constant_cache_key(constraints: list[z3.BoolRef]) -> int:
            _ = constraints
            return 1

        monkeypatch.setattr(solver, "_make_cache_key", constant_cache_key)
        x = z3.Int("x_cached_collision")

        first = solver.check_sat_cached([x == 1])
        second = solver.check_sat_cached([x == 2])

        assert first.is_sat and first.model is not None
        assert second.is_sat and second.model is not None
        assert z3.is_true(second.model.eval(x == 2, model_completion=True))
        assert not z3.is_true(second.model.eval(x == 1, model_completion=True))

    def test_check_sat_cached_does_not_cache_deadline_unknown(self) -> None:
        solver = IncrementalSolver()
        x = z3.Int("x_cached_unknown_recheck")
        solver.set_deadline(time.perf_counter() - 1.0)

        first = solver.check_sat_cached([x == 3])
        solver.set_deadline(None)
        second = solver.check_sat_cached([x == 3])

        assert first.is_unknown
        assert second.is_sat
        assert second.model is not None
        assert z3.is_true(second.model.eval(x == 3, model_completion=True))

    def test_check_sat_result_does_not_cache_unknown(self, monkeypatch: pytest.MonkeyPatch) -> None:
        solver = IncrementalSolver()
        x = z3.Int("x_result_unknown_recheck")

        def unknown_check(*assumptions: z3.BoolRef) -> z3.CheckSatResult:
            _ = assumptions
            return z3.unknown

        monkeypatch.setattr(solver.solver, "check", unknown_check)
        first = solver.check_sat_result([x == 3])

        monkeypatch.undo()
        second = solver.check_sat_result([x == 3])

        assert first.is_unknown
        assert second.is_sat

    def test_check_sat_result_skips_check_cache_for_bitvector_assumptions(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        solver = IncrementalSolver()
        x = z3.BitVec("x_skip_check_cache_bv", 64)

        def raise_check_cache_key(_assumptions: tuple[z3.BoolRef, ...]) -> int:
            raise AssertionError("bit-vector checks should bypass low-level check cache")

        monkeypatch.setattr(solver, "_make_check_cache_key", raise_check_cache_key)

        result = solver.check_sat_result([x == 0])

        assert result.is_sat

    def test_check_sat_cached_preserves_canceled_push_as_unknown(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Model-producing cached checks must not surface Z3 cancellation as an engine error."""
        solver = IncrementalSolver()
        x = z3.Int("x_cached_push_canceled")

        def raise_canceled() -> None:
            raise z3.Z3Exception("push canceled")

        monkeypatch.setattr(solver.solver, "push", raise_canceled)

        result = solver.check_sat_cached([x > 0])

        assert (result.is_unknown, result.is_sat, result.is_unsat) == (True, False, False)

    def test_get_model(self) -> None:
        solver = IncrementalSolver()
        x = z3.Int("x")
        model = solver.get_model([x == 2])
        assert model is not None

    def test_get_model_string(self) -> None:
        solver = IncrementalSolver()
        x = z3.Int("x")
        model_str = solver.get_model_string([x == 2])
        assert model_str is not None

    def test_simplify(self) -> None:
        solver = IncrementalSolver()
        x = z3.Int("x")
        simplified = solver.simplify(x + 0)
        assert z3.is_expr(simplified)

    def test_get_stats(self) -> None:
        solver = IncrementalSolver()
        stats = solver.get_stats()
        assert "queries" in stats and "cache_hits" in stats
        assert stats["sat_results"] == 0
        assert stats["unsat_results"] == 0
        assert stats["unknown_results"] == 0

    def test_get_stats_counts_solver_outcomes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        solver = IncrementalSolver(use_cache=False)
        x = z3.Int("x_stats_outcomes")

        assert solver.check(x == 1).is_sat
        assert solver.check(x == 1, x == 2).is_unsat

        def unknown_check(*assumptions: z3.BoolRef) -> z3.CheckSatResult:
            _ = assumptions
            return z3.unknown

        monkeypatch.setattr(solver.solver, "check", unknown_check)

        assert solver.check(x == 3).is_unknown

        stats = solver.get_stats()
        assert stats["queries"] == 3
        assert stats["sat_results"] == 1
        assert stats["unsat_results"] == 1
        assert stats["unknown_results"] == 1

    def test_reset_clears_all_per_run_solver_stats(self) -> None:
        solver = IncrementalSolver(use_cache=False)
        x = z3.Int("x_stats_reset")

        assert solver.check(x == 1).is_sat
        assert solver.check(x == 1, x == 2).is_unsat

        solver.reset()

        stats = solver.get_stats()
        assert stats["queries"] == 0
        assert stats["sat_results"] == 0
        assert stats["unsat_results"] == 0
        assert stats["unknown_results"] == 0
        assert stats["cache_hits"] == 0
        assert stats["solver_time_ms"] == 0.0

    def test_z3_ast_translation_cache_reuses_same_context_expression(self) -> None:
        ctx = z3.Context()
        x = z3.Int("x_ast_cache", ctx=ctx)
        constraint = x > 0
        solver = IncrementalSolver()

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
        solver = IncrementalSolver()

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
        solver = IncrementalSolver()

        solver.add(constraint)
        solver.add(constraint)

        stats = solver.get_stats()
        assert stats["z3_ast_cache_misses"] == 0
        assert stats["z3_ast_cache_hits"] == 0
        assert stats["z3_ast_cache_size"] == 0
        assert solver.check().is_sat

    def test_expr_equal_with_colliding_ids(self) -> None:
        """P1: IncrementalSolver.expr_equal must not treat colliding IDs across contexts as equal."""
        ctx1 = z3.Context()
        ctx2 = z3.Context()
        x1 = z3.Int("x", ctx1) > 0
        x2 = z3.Int("y", ctx2) > 0

        solver = IncrementalSolver()
        assert not solver.expr_equal(x1, x2)
