"""Tests for exact integer path-fact solver shortcuts."""

from __future__ import annotations

import pytest
import z3

from pysymex._internal.core.solver.engine.incremental import IncrementalSolver
from pysymex._internal.core.solver.engine.policies import path_may_be_feasible
from pysymex._internal.core.solver.facts import (
    PathFactDecision,
    PathFactPolicy,
    clear_path_fact_caches,
)


def test_path_facts_prove_integer_bound_contradiction() -> None:
    x = z3.Int("path_fact_unsat_x")

    decision = PathFactPolicy.classify([x >= 0, x < 0])

    assert decision is PathFactDecision.UNSAT


def test_path_facts_flatten_conjunction_before_classification() -> None:
    x = z3.Int("path_fact_and_unsat_x")

    decision = PathFactPolicy.classify([z3.And(x >= 0, x < 0)])

    assert decision is PathFactDecision.UNSAT


def test_path_facts_prove_negated_integer_bound_contradiction() -> None:
    x = z3.Int("path_fact_not_x")

    decision = PathFactPolicy.classify([x >= 0, z3.Not(x >= 0)])

    assert decision is PathFactDecision.UNSAT


def test_path_facts_prove_disequality_contradiction() -> None:
    x = z3.Int("path_fact_eq_x")

    decision = PathFactPolicy.classify([x == 3, x != 3])

    assert decision is PathFactDecision.UNSAT


def test_path_facts_prove_suffix_entailed_by_known_sat_prefix() -> None:
    x = z3.Int("path_fact_entailed_x")

    decision = PathFactPolicy.classify(
        [x >= 0, x > -1],
        known_sat_prefix_len=1,
        allow_entailed=True,
    )

    assert decision is PathFactDecision.ENTAILED


def test_path_facts_adjust_known_prefix_after_conjunction_flattening() -> None:
    x = z3.Int("path_fact_and_prefix_x")

    decision = PathFactPolicy.classify(
        [z3.And(x >= 0, x < 3), x > -1],
        known_sat_prefix_len=1,
        allow_entailed=True,
    )

    assert decision is PathFactDecision.ENTAILED


def test_path_facts_prove_supported_bounds_sat() -> None:
    x = z3.Int("path_fact_supported_sat_x")
    y = z3.Int("path_fact_supported_sat_y")

    decision = PathFactPolicy.classify(
        [x >= 0, x <= 3, y != 2],
        allow_supported_sat=True,
    )

    assert decision is PathFactDecision.SAT


def test_path_facts_reject_fully_excluded_finite_integer_range() -> None:
    x = z3.Int("path_fact_excluded_range_x")

    decision = PathFactPolicy.classify(
        [x >= 1, x <= 2, x != 1, x != 2],
        allow_supported_sat=True,
    )

    assert decision is PathFactDecision.UNSAT


def test_path_facts_do_not_claim_entailed_without_known_sat_prefix() -> None:
    x = z3.Int("path_fact_no_prefix_x")

    decision = PathFactPolicy.classify([x >= 0, x > -1], allow_entailed=True)

    assert decision is None


def test_path_facts_support_conservative_prior_entailment_for_may_feasible() -> None:
    x = z3.Int("path_fact_prior_x")

    decision = PathFactPolicy.classify(
        [x >= 0, x > -1],
        allow_entailed=True,
        allow_prior_entailment=True,
    )

    assert decision is PathFactDecision.ENTAILED


def test_prior_entailment_still_reports_supported_contradictions() -> None:
    x = z3.Int("path_fact_prior_unsat_x")

    decision = PathFactPolicy.classify(
        [x >= 0, x < 0],
        allow_entailed=True,
        allow_prior_entailment=True,
    )

    assert decision is PathFactDecision.UNSAT


def test_path_facts_fall_back_for_unsupported_suffix() -> None:
    x = z3.Int("path_fact_unsupported_x")
    y = z3.Int("path_fact_unsupported_y")

    decision = PathFactPolicy.classify(
        [x >= 0, x + y > 1],
        known_sat_prefix_len=1,
        allow_entailed=True,
    )

    assert decision is None


def test_path_facts_stop_generic_classification_at_first_unsupported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pysymex._internal.core.solver import facts

    x = z3.Int("path_fact_mixed_x")
    y = z3.Int("path_fact_mixed_y")
    constraints = [x + y > 1, x >= 0, x < 0]
    calls: list[z3.BoolRef] = []
    real_atom_from_expr = facts.atom_from_expr

    def counted_atom_from_expr(expr: z3.BoolRef) -> object:
        calls.append(expr)
        return real_atom_from_expr(expr)

    monkeypatch.setattr(facts, "atom_from_expr", counted_atom_from_expr)

    decision = PathFactPolicy.classify(constraints, allow_supported_sat=True)

    assert decision is None
    assert calls == [constraints[0]]


def test_path_facts_stop_no_prefix_entailment_at_first_unsupported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pysymex._internal.core.solver import facts

    x = z3.Int("path_fact_mixed_entail_x")
    y = z3.Int("path_fact_mixed_entail_y")
    constraints = [x + y > 1, x >= 0, x < 0]
    calls: list[z3.BoolRef] = []
    real_atom_from_expr = facts.atom_from_expr

    def counted_atom_from_expr(expr: z3.BoolRef) -> object:
        calls.append(expr)
        return real_atom_from_expr(expr)

    monkeypatch.setattr(facts, "atom_from_expr", counted_atom_from_expr)

    decision = PathFactPolicy.classify(
        constraints,
        allow_entailed=True,
        allow_supported_sat=True,
    )

    assert decision is None
    assert calls == [constraints[0]]


def test_incremental_solver_short_circuits_exact_unsat_without_z3_query() -> None:
    solver = IncrementalSolver(use_cache=False)
    x = z3.Int("path_fact_solver_unsat_x")

    result = solver.check_sat_result([x >= 0, x < 0])

    assert result.is_unsat
    assert solver.get_stats()["queries"] == 0


def test_incremental_solver_short_circuits_entailed_known_prefix_without_z3_query() -> None:
    solver = IncrementalSolver(use_cache=False)
    x = z3.Int("path_fact_solver_entailed_x")

    result = solver.check_sat_result(
        [x >= 0, x > -1],
        known_sat_prefix_len=1,
    )

    assert result.is_sat
    assert solver.get_stats()["queries"] == 0


def test_incremental_solver_short_circuits_supported_sat_without_z3_query() -> None:
    solver = IncrementalSolver(use_cache=False)
    x = z3.Int("path_fact_solver_supported_sat_x")
    y = z3.Int("path_fact_solver_supported_sat_y")

    result = solver.check_sat_result([x >= 0, x <= 3, y != 2])

    assert result.is_sat
    assert result.model is None
    assert solver.get_stats()["queries"] == 0


def test_incremental_solver_uses_z3_for_unsupported_query() -> None:
    solver = IncrementalSolver(use_cache=False)
    x = z3.Int("path_fact_solver_fallback_x")
    y = z3.Int("path_fact_solver_fallback_y")

    result = solver.check_sat_result([x + y > 1])

    assert result.is_sat
    assert solver.get_stats()["queries"] == 1


def test_policy_uses_entailed_fact_as_conservative_may_feasible() -> None:
    x = z3.Int("path_fact_policy_x")

    assert path_may_be_feasible(
        [x >= 0, x > -1],
        known_sat_prefix_len=1,
    )


def test_policy_uses_supported_sat_as_conservative_may_feasible() -> None:
    x = z3.Int("path_fact_policy_supported_sat_x")

    assert path_may_be_feasible([x >= 0])


def test_clear_path_fact_caches_preserves_classification_behavior() -> None:
    x = z3.Int("path_fact_clear_x")

    assert PathFactPolicy.classify([x >= 0, x < 0]) is PathFactDecision.UNSAT

    clear_path_fact_caches()

    assert PathFactPolicy.classify([x >= 0, x < 0]) is PathFactDecision.UNSAT
