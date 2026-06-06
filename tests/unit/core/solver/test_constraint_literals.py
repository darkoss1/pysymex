"""Tests for exact solver literal classification fast paths."""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

import z3
import pytest

from pysymex.core.solver.constraints import hashing
from pysymex.core.solver.constraints import literals
from pysymex.core.solver.constraints.literals import clear_exact_bool_literal_cache
from pysymex.core.solver.constraints.literals import exact_bool_literal
from pysymex.core.solver.engine.incremental import IncrementalSolver


def test_exact_bool_literal_classifies_constant_integer_comparisons() -> None:
    """Integer literal comparisons are decidable without invoking Z3 simplification."""
    assert exact_bool_literal(z3.IntVal(3) < z3.IntVal(3)) is False
    assert exact_bool_literal(z3.IntVal(3) <= z3.IntVal(3)) is True
    assert exact_bool_literal(z3.IntVal(4) > z3.IntVal(9)) is False
    assert exact_bool_literal(z3.IntVal(4) >= z3.IntVal(4)) is True
    assert exact_bool_literal(z3.IntVal(4) == z3.IntVal(4)) is True
    assert exact_bool_literal(z3.Distinct(z3.IntVal(4), z3.IntVal(4))) is False


def test_exact_bool_literal_leaves_symbolic_comparisons_for_solver() -> None:
    """Symbolic comparisons remain undecided at the syntactic boundary."""
    x = z3.Int("literal_boundary_x")

    assert exact_bool_literal(x < z3.IntVal(3)) is None


def test_exact_bool_literal_classifies_small_modulo_intervals() -> None:
    """Small positive-modulo intervals prove obvious bounds without Z3."""
    x = z3.Int("literal_interval_x")
    index = z3.IntVal(2) + (x % 2)

    assert exact_bool_literal(index < z3.IntVal(-4)) is False
    assert exact_bool_literal(z3.IntVal(4) <= index) is False
    assert exact_bool_literal(z3.Or(index < z3.IntVal(-4), z3.IntVal(4) <= index)) is False
    assert exact_bool_literal(z3.And(index >= z3.IntVal(2), index < z3.IntVal(4))) is True
    assert exact_bool_literal(z3.Not(z3.And(index >= z3.IntVal(-4), index < z3.IntVal(4)))) is False


def test_exact_bool_literal_keeps_ambiguous_interval_comparisons_unknown() -> None:
    """Overlapping ranges are not guessed as true or false."""
    x = z3.Int("literal_interval_unknown_x")
    index = z3.IntVal(2) + (x % 2)

    assert exact_bool_literal(index == z3.IntVal(2)) is None
    assert exact_bool_literal(index < z3.IntVal(3)) is None
    assert exact_bool_literal((x % 2) == z3.IntVal(0)) is None


def test_exact_bool_literal_reuses_wrapper_cached_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expr = z3.IntVal(3) < z3.IntVal(4)

    assert exact_bool_literal(expr) is True

    def fail_uncached(_expr: z3.BoolRef) -> bool | None:
        raise AssertionError("cached exact literal result should be reused")

    monkeypatch.setattr(literals, "_uncached_exact_bool_literal", fail_uncached)

    assert exact_bool_literal(expr) is True


def test_exact_bool_literal_reuses_ast_cached_result_across_wrappers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_exact_bool_literal_cache()
    expr = z3.IntVal(3) < z3.IntVal(4)

    assert exact_bool_literal(expr) is True
    as_ast = cast("Callable[[], object]", getattr(expr, "as_ast"))
    bool_ref = cast("Callable[[object, object], object]", z3.BoolRef)
    equivalent_wrapper = cast("z3.BoolRef", bool_ref(as_ast(), expr.ctx))

    def fail_uncached(_expr: z3.BoolRef) -> bool | None:
        raise AssertionError("cached exact literal result should be reused across wrappers")

    monkeypatch.setattr(literals, "_uncached_exact_bool_literal", fail_uncached)

    assert equivalent_wrapper is not expr
    assert exact_bool_literal(equivalent_wrapper) is True


def test_check_sat_cached_short_circuits_constant_false_comparison(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Model-producing queries must not call Z3 for syntactic constant falsehoods."""
    solver = IncrementalSolver()

    def fail_check(*_args: object, **_kwargs: object) -> z3.CheckSatResult:
        raise AssertionError("constant false comparison should not query Z3")

    monkeypatch.setattr(solver.solver, "check", fail_check)

    result = solver.check_sat_cached([z3.IntVal(3) < z3.IntVal(3)])

    assert result.is_unsat
    assert solver.get_stats()["queries"] == 0


def test_check_sat_result_drops_constant_true_comparison(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """May-SAT checks drop syntactic constant truths before solver dispatch."""
    x = z3.Int("literal_true_comparison_x")
    solver = IncrementalSolver()
    seen_assumptions: list[z3.BoolRef] = []
    solver_check = solver.solver.check

    def recording_check(*assumptions: z3.BoolRef) -> z3.CheckSatResult:
        seen_assumptions.extend(assumptions)
        return solver_check(*assumptions)

    monkeypatch.setattr(solver.solver, "check", recording_check)

    result = solver.check_sat_result([z3.IntVal(2) < z3.IntVal(3), x == 1])

    assert result.is_sat
    assert len(seen_assumptions) == 1
    assert z3.eq(seen_assumptions[0], x == 1)


def test_check_sat_result_short_circuits_constant_false_before_cache_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exact falsehoods must not pay structural-hash/cache setup overhead."""
    x = z3.Int("literal_false_cache_x")
    solver = IncrementalSolver()

    def fail_structural_hash(*_args: object, **_kwargs: object) -> int:
        raise AssertionError("constant false comparison should bypass cache-key hashing")

    monkeypatch.setattr(hashing, "structural_hash", fail_structural_hash)

    result = solver.check_sat_result([x == 1, z3.IntVal(4) < z3.IntVal(3)])

    assert result.is_unsat


def test_check_sat_result_adjusts_known_prefix_after_dropping_true_literals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Known-SAT prefix ownership is adjusted when exact truths are removed."""
    x = z3.Int("literal_prefix_adjust_x")
    solver = IncrementalSolver()
    synced_prefixes: list[list[z3.BoolRef]] = []

    def record_sync_path(target_prefix: list[z3.BoolRef]) -> None:
        synced_prefixes.append(target_prefix)

    monkeypatch.setattr(solver, "_sync_path", record_sync_path)

    result = solver.check_sat_result(
        [z3.IntVal(1) == z3.IntVal(1), x == 1, x < 3],
        known_sat_prefix_len=2,
    )

    assert result.is_sat
    assert len(synced_prefixes) == 1
    assert len(synced_prefixes[0]) == 1
    assert z3.eq(synced_prefixes[0][0], x == 1)


def test_check_sat_result_uses_temporary_assumptions_for_suffix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Suffix queries should not allocate a temporary solver push/pop scope."""
    x = z3.Int("literal_suffix_assumption_x")
    solver = IncrementalSolver()

    def fail_push_or_pop() -> None:
        raise AssertionError("suffix query should use check assumptions")

    monkeypatch.setattr(solver, "push", fail_push_or_pop)
    monkeypatch.setattr(solver, "pop", fail_push_or_pop)

    sat_result = solver.check_sat_result([x >= 0, x < 3])
    unsat_result = solver.check_sat_result([x >= 0, x < 0])

    assert sat_result.is_sat
    assert unsat_result.is_unsat
    assert solver.active_path == []


def test_check_sat_result_uses_assumptions_for_large_sliced_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Large sliced prefixes avoid expensive temporary sync scopes."""
    x = z3.Int("literal_large_prefix_assumption_x")
    prefix = [x >= z3.IntVal(index) for index in range(16)]
    suffix = [x < 20]
    solver = IncrementalSolver()
    synced_prefixes: list[list[z3.BoolRef]] = []
    seen_assumption_counts: list[int] = []
    solver_check = solver.solver.check

    def keep_full_prefix(
        sliced_prefix: list[z3.BoolRef],
        _query: list[z3.BoolRef] | z3.BoolRef,
    ) -> list[z3.BoolRef]:
        return sliced_prefix

    def record_sync_path(target_prefix: list[z3.BoolRef]) -> None:
        synced_prefixes.append(target_prefix)

    def record_check(*assumptions: z3.BoolRef) -> z3.CheckSatResult:
        seen_assumption_counts.append(len(assumptions))
        return solver_check(*assumptions)

    monkeypatch.setattr(solver, "_slice_prefix_for_suffix", keep_full_prefix)
    monkeypatch.setattr(solver, "_sync_path", record_sync_path)
    monkeypatch.setattr(solver.solver, "check", record_check)

    result = solver.check_sat_result([*prefix, *suffix], known_sat_prefix_len=len(prefix))

    assert result.is_sat
    assert synced_prefixes == [[]]
    assert seen_assumption_counts == [len(prefix) + len(suffix)]
