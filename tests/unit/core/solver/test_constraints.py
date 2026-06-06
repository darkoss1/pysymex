from concurrent.futures import ThreadPoolExecutor

import pytest
import z3

import pysymex.core.solver.constraints.hashing as hashing_mod
import pysymex.core.solver.constraints.theory as theory_mod
from pysymex.core.solver.constraints.contradictions import quick_contradiction_check
from pysymex.core.solver.constraints.hashing import (
    ConstraintHasher,
    get_bitvec_val,
    get_float64_val,
    get_int_val,
    get_real_val,
    structural_hash,
    structural_hash_sorted,
)
from pysymex.core.solver.constraints.simplification import (
    simplify_constraints,
    tactic_simplify,
)
from pysymex.core.solver.constraints.subsumption import remove_subsumed


def test_core_constraint_exports_use_direct_owners() -> None:
    import pysymex.core as core

    assert core.quick_contradiction_check is quick_contradiction_check
    assert core.remove_subsumed is remove_subsumed
    assert core.simplify_constraints is simplify_constraints


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
    assert get_int_val(7) is get_int_val(7)


def test_cached_float64_literals_preserve_signed_zero() -> None:
    """Scenario: finite Float64 literals include signed zero; expected exact cache keys."""
    positive_zero = get_float64_val(0.0)
    negative_zero = get_float64_val(-0.0)

    assert positive_zero is get_float64_val(0.0)
    assert negative_zero is get_float64_val(-0.0)
    assert positive_zero is not negative_zero
    assert not z3.eq(positive_zero, negative_zero)


def test_cached_real_literals_reuse_common_values() -> None:
    """Scenario: repeated common Real literal; expected shared Z3 wrapper."""
    first = get_real_val(1)
    second = get_real_val("1")

    assert first is second
    assert z3.eq(first, z3.RealVal(1))


def test_cached_bitvec_literals_reuse_common_values_and_widths() -> None:
    """Scenario: repeated BitVec literal; expected cache key includes width."""
    first = get_bitvec_val(7, 8)
    second = get_bitvec_val(7, 8)
    wider = get_bitvec_val(7, 16)

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


def test_simplify_constraints() -> None:
    """Scenario: constraints include true literal; expected true removed after simplify."""
    x = z3.Int("x")
    simplified = simplify_constraints([z3.BoolVal(True), x > 0])
    assert len(simplified) == 1


def test__tactic_simplify() -> None:
    """Scenario: tactic simplify called with simple constraints; expected list output."""
    x = z3.Int("x")
    simplified = tactic_simplify([x > 0, x < 10])
    assert isinstance(simplified, list)


def test_quick_contradiction_check() -> None:
    """Scenario: direct contradiction pair c and not c; expected contradiction detected."""
    c = z3.Bool("c")
    assert quick_contradiction_check([c, z3.Not(c)]) is True


def test_quick_contradiction_check_shared_cache_is_thread_safe() -> None:
    """Scenario: concurrent cache hits and writes; expected deterministic results."""
    x = z3.Int("quick_thread_x")
    contradictory = [x > 0, z3.Not(x > 0)]
    satisfiable = [x > 0, x < 10]

    def check(index: int) -> bool:
        constraints = contradictory if index % 2 == 0 else satisfiable
        return quick_contradiction_check(constraints)

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(check, range(200)))

    assert results == [index % 2 == 0 for index in range(200)]


def test_remove_subsumed() -> None:
    """Scenario: duplicate structural constraints; expected deduplicated output."""
    c = z3.Bool("d")
    assert remove_subsumed([c, c]) == [c]


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
