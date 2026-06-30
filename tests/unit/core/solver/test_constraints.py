import pytest
import z3

import pysymex._internal.core.solver.constraints.hashing as hashing_mod
import pysymex._internal.core.solver.constraints.theory as theory_mod
from pysymex._internal.core.solver.constraints.hashing import (
    ConstraintHasher,
    structural_hash,
    structural_hash_sorted,
)
from pysymex._internal.core.solver.constraints.simplification import (
    simplify_expr,
)
from pysymex._internal.core.solver.constraints.values import ConstraintValues


def test_structural_hash() -> None:
    """Scenario: same ordered constraints hashed twice; expected stable hash value."""
    x = z3.Int("x")
    constraints = [x > 0, x < 10]
    assert structural_hash(constraints) == structural_hash(constraints)


def test_structural_hash_sorted() -> None:
    """Scenario: same constraints in different order; expected order-independent same hash."""
    x = z3.Int("x")
    a = [x > 0, x < 10]
    b = [x < 10, x > 0]
    assert structural_hash_sorted(a) == structural_hash_sorted(b)


def test_cached_int_literals_reuse_common_values() -> None:
    """Scenario: repeated common Int literal; expected shared Z3 wrapper."""
    assert ConstraintValues.int(7) is ConstraintValues.int(7)


def test_cached_float64_literals_preserve_signed_zero() -> None:
    """Scenario: finite Float64 literals include signed zero; expected exact cache keys."""
    positive_zero = ConstraintValues.float64(0.0)
    negative_zero = ConstraintValues.float64(-0.0)

    assert positive_zero is ConstraintValues.float64(0.0)
    assert negative_zero is ConstraintValues.float64(-0.0)
    assert positive_zero is not negative_zero
    assert not z3.eq(positive_zero, negative_zero)


def test_cached_real_literals_reuse_common_values() -> None:
    """Scenario: repeated common Real literal; expected shared Z3 wrapper."""
    first = ConstraintValues.real(1)
    second = ConstraintValues.real("1")

    assert first is second
    assert z3.eq(first, z3.RealVal(1))


def test_cached_bitvec_literals_reuse_common_values_and_widths() -> None:
    """Scenario: repeated BitVec literal; expected cache key includes width."""
    first = ConstraintValues.bitvec(7, 8)
    second = ConstraintValues.bitvec(7, 8)
    wider = ConstraintValues.bitvec(7, 16)

    assert first is second
    assert first.size() == 8
    assert wider.size() == 16
    assert first is not wider


def test_bitvector_theory_cache_validates_expression_collision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scenario: forced cache-key collision; expected stale expression result ignored."""
    theory_mod.clear_bitvector_theory_cache()

    def constant_cache_key(_expr: z3.ExprRef) -> tuple[int, int]:
        return (1, 1)

    monkeypatch.setattr(theory_mod, "_bitvector_theory_cache_key", constant_cache_key)

    bitvec = z3.BitVec("bitvector_theory_collision_bv", 8)
    integer = z3.Int("bitvector_theory_collision_int")

    assert theory_mod.is_bitvector_smt_theory(bitvec == 1) is True
    assert theory_mod.is_bitvector_smt_theory(integer > 0) is False


def test_simplify_expr_uses_engine_canonical_options(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scenario: SSoT simplify called; expected canonical cheap Z3 options."""
    captured: dict[str, object] = {}
    original_simplify = z3.simplify

    def fake_simplify(expr: z3.ExprRef, **kwargs: object) -> z3.ExprRef:
        captured.update(kwargs)
        return original_simplify(expr)

    monkeypatch.setattr(z3, "simplify", fake_simplify)

    x = z3.Int("canonical_simplify_x")
    simplify_expr(x + 1 <= 3)

    assert captured == {
        "sort_sums": True,
        "bv_sort_ac": True,
    }


def test_symbolic_query_simplification_routes_through_ssoT(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scenario: query planner simplifies conjunctions; expected SSoT owner used."""
    import pysymex._internal.core.solver.query.planner as planner

    calls = 0
    original_simplify = planner.simplify_expr

    def fake_simplify(expr: z3.ExprRef) -> z3.ExprRef:
        nonlocal calls
        calls += 1
        return original_simplify(expr)

    monkeypatch.setattr(planner, "simplify_expr", fake_simplify)
    planner.clear_symbolic_query_caches()

    x = z3.Int("planner_ssoT_x")
    query = planner.symbolic_query([x > 0, x < 5])

    assert query.simplified_conjunction() is not None
    assert calls == 1


class TestConstraintHasher:
    """Behavioral tests for ConstraintHasher lifecycle and cache semantics."""

    def test_hash_expr(self) -> None:
        """Scenario: hashing one expression; expected cached value equals ExprRef.hash()."""
        hasher = ConstraintHasher()
        expr = z3.Int("x") + 1 == 2
        assert hasher.hash_expr(expr) == expr.hash()

    def test___init__(self) -> None:
        """Scenario: non-positive cache limit; expected immediate ValueError."""
        with pytest.raises(ValueError):
            ConstraintHasher(max_cache_size=0)

    def test_structural_hash(self) -> None:
        """Scenario: same live expressions hashed repeatedly; expected stable hash."""
        hasher = ConstraintHasher()
        x = z3.Int("x")
        constraints: list[z3.BoolRef] = [x + i == i for i in range(256)]
        first = hasher.structural_hash(constraints)
        second = hasher.structural_hash(constraints)
        assert first == second

    def test_long_sequence_cache_revalidates_mutated_constraint_lists(self) -> None:
        """Scenario: long cached list mutates; expected recomputed hash for new sequence."""
        hasher = ConstraintHasher()
        reference_hasher = ConstraintHasher()
        x = z3.Int("seq_cache_x")
        y = z3.Int("seq_cache_y")
        constraints: list[z3.BoolRef] = [x + i == y - i for i in range(128)]
        first = hasher.structural_hash(constraints)

        constraints[0] = x == 99
        mutated = hasher.structural_hash(constraints)
        reference = reference_hasher.structural_hash(constraints)

        assert mutated == reference
        assert mutated != first

    def test_new_hasher_per_phase_matches_codebase_contract(self) -> None:
        """Scenario: each phase creates a new hasher; expected each phase remains self-consistent."""
        x = z3.Int("x")
        phase_a_constraints: list[z3.BoolRef] = [x + i == i for i in range(128)]
        phase_b_constraints: list[z3.BoolRef] = [x - i == i for i in range(128)]

        phase_a_hasher = ConstraintHasher()
        phase_b_hasher = ConstraintHasher()

        phase_a_hash = phase_a_hasher.structural_hash(phase_a_constraints)
        phase_b_hash = phase_b_hasher.structural_hash(phase_b_constraints)
        assert phase_a_hash != phase_b_hash

    def test_clear(self) -> None:
        """Scenario: cache populated then cleared; expected cache size to become zero."""
        hasher = ConstraintHasher()
        expr = z3.Int("a") == 1
        hasher.hash_expr(expr)
        hasher.clear()
        assert hasher.cache_size() == 0

    def test_cache_size(self) -> None:
        """Scenario: normal Z3 wrappers use attached hashes, not fallback cache entries."""
        hasher = ConstraintHasher()
        expr = z3.Int("a") == 1
        hasher.hash_expr(expr)
        assert hasher.cache_size() == 0

    def test_fallback_cache_limit_triggers_clear_before_new_insert(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Scenario: fallback cache reaches limit; expected clear then current expression hash."""

        def reject_attached_hash(_constraint: z3.ExprRef, _computed: int) -> bool:
            return False

        monkeypatch.setattr(hashing_mod, "_try_attach_hash", reject_attached_hash)
        hasher = ConstraintHasher(max_cache_size=2)
        expr_a = z3.Int("a") == 1
        expr_b = z3.Int("b") == 2
        expr_c = z3.Int("c") == 3

        hasher.hash_expr(expr_a)
        hasher.hash_expr(expr_b)
        hasher.hash_expr(expr_c)

        assert hasher.cache_size() == 1

    @pytest.mark.slow
    def test_long_lived_hasher_can_stale_hit_after_id_reuse(self) -> None:
        """Scenario: one hasher reused across short-lived expressions; expected no stale hits."""
        hasher = ConstraintHasher()
        stale_hits = 0
        for i in range(50_000):
            expr = z3.Int(f"v_{i}") == i
            cached = hasher.hash_expr(expr)
            if cached != expr.hash():
                stale_hits += 1
        assert stale_hits == 0
