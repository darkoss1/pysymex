from __future__ import annotations

import pytest
import z3

from pysymex._internal.contracts.ir.evidence import TheoryFeature, UnsupportedReason
from pysymex._internal.contracts.quantifiers.lower.policy import (
    ConcreteRange,
    QuantifierLoweringError,
    QuantifierLoweringPolicy,
)
from pysymex._internal.contracts.quantifiers.lowering import (
    find_quantifier_occurrences,
    lower_condition_quantifiers,
)
from pysymex._internal.contracts.solver.query import theory_profile_for_constraints
from pysymex._internal.core.solver.constraints.simplification import simplify_expr


def test_concrete_bounded_forall_is_finite_expanded_without_quantifier_theory() -> None:
    formula = lower_condition_quantifiers("forall(i, 0 <= i < 3, i >= 0)", {})

    assert TheoryFeature.QUANTIFIER not in theory_profile_for_constraints([formula])
    solver = z3.Solver()
    solver.add(z3.Not(formula))
    assert solver.check() == z3.unsat


def test_concrete_bounded_exists_and_unique_are_expanded() -> None:
    exists_formula = lower_condition_quantifiers("exists(i, 0 <= i < 3, i == 2)", {})
    unique_formula = lower_condition_quantifiers("exists!(i, 0 <= i < 4, i == 2)", {})
    not_unique_formula = lower_condition_quantifiers("exists!(i, 0 <= i < 4, i >= 2)", {})

    assert z3.is_true(simplify_expr(exists_formula))
    assert z3.is_true(simplify_expr(unique_formula))
    assert z3.is_false(simplify_expr(not_unique_formula))


def test_default_policy_expands_finite_domain_beyond_old_internal_cap() -> None:
    formula = lower_condition_quantifiers("forall(i, 0 <= i < 65, i >= 0)", {})

    solver = z3.Solver()
    solver.add(z3.Not(formula))
    assert solver.check() == z3.unsat


def test_explicit_quantifier_expansion_limit_remains_supported() -> None:
    policy = QuantifierLoweringPolicy(max_expansion=64)

    with pytest.raises(QuantifierLoweringError):
        lower_condition_quantifiers("forall(i, 0 <= i < 65, i >= 0)", {}, policy=policy)


def test_symbolic_bounded_range_is_guarded_by_explicit_policy() -> None:
    n = z3.Int("n")
    xs = z3.Array("xs", z3.IntSort(), z3.IntSort())
    policy = QuantifierLoweringPolicy(symbolic_ranges={n.sexpr(): ConcreteRange(0, 3)})

    formula = lower_condition_quantifiers(
        "forall(i, 0 <= i < n, xs[i] >= 0)",
        {"n": n, "xs": xs},
        policy=policy,
    )

    assert TheoryFeature.QUANTIFIER not in theory_profile_for_constraints([formula])

    safe_solver = z3.Solver()
    safe_solver.add(n == 2, z3.Select(xs, z3.IntVal(0)) >= 0)
    safe_solver.add(z3.Select(xs, z3.IntVal(1)) >= 0, z3.Not(formula))
    assert safe_solver.check() == z3.unsat

    unsafe_solver = z3.Solver()
    unsafe_solver.add(n == 2, z3.Select(xs, z3.IntVal(1)) < 0, formula)
    assert unsafe_solver.check() == z3.unsat


def test_unbounded_symbolic_range_is_unsupported_by_default() -> None:
    n = z3.Int("n")

    with pytest.raises(QuantifierLoweringError) as exc_info:
        lower_condition_quantifiers("forall(i, 0 <= i < n, i >= 0)", {"n": n})

    assert exc_info.value.unsupported_reason is UnsupportedReason.UNBOUNDED_QUANTIFIER


def test_native_quantifier_fallback_is_explicit_policy() -> None:
    n = z3.Int("n")
    policy = QuantifierLoweringPolicy(allow_native_z3=True)

    formula = lower_condition_quantifiers(
        "forall(i, 0 <= i < n, i >= 0)",
        {"n": n},
        policy=policy,
    )

    assert TheoryFeature.QUANTIFIER in theory_profile_for_constraints([formula])


def test_quantifier_occurrence_keeps_predicate_ir_source_parts() -> None:
    occurrences = find_quantifier_occurrences("x > 0 and forall(i, 0 <= i < 2, i >= 0)")

    assert len(occurrences) == 1
    assert occurrences[0].predicate_ir.variable == "i"
    assert occurrences[0].predicate_ir.bound_source == "0 <= i < 2"
    assert occurrences[0].predicate_ir.body_source == "i >= 0"


def test_quantifier_parser_accepts_top_level_body_commas() -> None:
    formula = lower_condition_quantifiers("forall(i, 0 <= i < 2, max(i, 0) >= 0)", {})

    solver = z3.Solver()
    solver.add(z3.Not(formula))
    assert solver.check() == z3.unsat
