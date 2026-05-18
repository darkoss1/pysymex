import pysymex.core.solver.constraints
import pytest
import z3


def test_structural_hash() -> None:
    """Scenario: same ordered constraints hashed twice; expected stable hash value."""
    x = z3.Int("x")
    constraints = [x > 0, x < 10]
    assert pysymex.core.solver.constraints.structural_hash(
        constraints
    ) == pysymex.core.solver.constraints.structural_hash(constraints)


def test_structural_hash_sorted() -> None:
    """Scenario: same constraints in different order; expected order-independent same hash."""
    x = z3.Int("x")
    a = [x > 0, x < 10]
    b = [x < 10, x > 0]
    assert pysymex.core.solver.constraints.structural_hash_sorted(
        a
    ) == pysymex.core.solver.constraints.structural_hash_sorted(b)


def test_structural_digest() -> None:
    """Scenario: same ordered constraints hashed twice; expected stable digest value."""
    x = z3.Int("x")
    constraints = [x > 0, x < 10]
    assert pysymex.core.solver.constraints.structural_digest(
        constraints
    ) == pysymex.core.solver.constraints.structural_digest(constraints)


def test_simplify_constraints() -> None:
    """Scenario: constraints include true literal; expected true removed after simplify."""
    x = z3.Int("x")
    simplified = pysymex.core.solver.constraints.simplify_constraints([z3.BoolVal(True), x > 0])
    assert len(simplified) == 1


def test__tactic_simplify() -> None:
    """Scenario: tactic simplify called with simple constraints; expected list output."""
    x = z3.Int("x")
    tactic_simplify = getattr(pysymex.core.solver.constraints, "_tactic_simplify")
    simplified = tactic_simplify([x > 0, x < 10])
    assert isinstance(simplified, list)


def test_quick_contradiction_check() -> None:
    """Scenario: direct contradiction pair c and not c; expected contradiction detected."""
    c = z3.Bool("c")
    assert pysymex.core.solver.constraints.quick_contradiction_check([c, z3.Not(c)]) is True


def test_remove_subsumed() -> None:
    """Scenario: duplicate structural constraints; expected deduplicated output."""
    c = z3.Bool("d")
    assert pysymex.core.solver.constraints.remove_subsumed([c, c]) == [c]


class TestConstraintHasher:
    """Behavioral tests for ConstraintHasher lifecycle and cache semantics."""

    def test_hash_expr(self) -> None:
        """Scenario: hashing one expression; expected cached value equals ExprRef.hash()."""
        hasher = pysymex.core.solver.constraints.ConstraintHasher()
        expr = z3.Int("x") + 1 == 2
        assert hasher.hash_expr(expr) == expr.hash()

    def test___init__(self) -> None:
        """Scenario: non-positive cache limit; expected immediate ValueError."""
        with pytest.raises(ValueError):
            pysymex.core.solver.constraints.ConstraintHasher(max_cache_size=0)

    def test_structural_hash(self) -> None:
        """Scenario: same live expressions hashed repeatedly; expected stable hash."""
        hasher = pysymex.core.solver.constraints.ConstraintHasher()
        x = z3.Int("x")
        constraints: list[z3.BoolRef] = [x + i == i for i in range(256)]
        first = hasher.structural_hash(constraints)
        second = hasher.structural_hash(constraints)
        assert first == second

    def test_new_hasher_per_phase_matches_codebase_contract(self) -> None:
        """Scenario: each phase creates a new hasher; expected each phase remains self-consistent."""
        x = z3.Int("x")
        phase_a_constraints: list[z3.BoolRef] = [x + i == i for i in range(128)]
        phase_b_constraints: list[z3.BoolRef] = [x - i == i for i in range(128)]

        phase_a_hasher = pysymex.core.solver.constraints.ConstraintHasher()
        phase_b_hasher = pysymex.core.solver.constraints.ConstraintHasher()

        phase_a_hash = phase_a_hasher.structural_hash(phase_a_constraints)
        phase_b_hash = phase_b_hasher.structural_hash(phase_b_constraints)
        assert phase_a_hash != phase_b_hash

    def test_clear(self) -> None:
        """Scenario: cache populated then cleared; expected cache size to become zero."""
        hasher = pysymex.core.solver.constraints.ConstraintHasher()
        expr = z3.Int("a") == 1
        hasher.hash_expr(expr)
        hasher.clear()
        assert hasher.cache_size() == 0

    def test_cache_size(self) -> None:
        """Scenario: cache receives one expression; expected reported size equals one."""
        hasher = pysymex.core.solver.constraints.ConstraintHasher()
        expr = z3.Int("a") == 1
        hasher.hash_expr(expr)
        assert hasher.cache_size() == 1

    def test_cache_limit_triggers_clear_before_new_insert(self) -> None:
        """Scenario: cache reaches limit; expected clear then insert current expression hash."""
        hasher = pysymex.core.solver.constraints.ConstraintHasher(max_cache_size=2)
        expr_a = z3.Int("a") == 1
        expr_b = z3.Int("b") == 2
        expr_c = z3.Int("c") == 3

        hasher.hash_expr(expr_a)
        hasher.hash_expr(expr_b)
        hasher.hash_expr(expr_c)

        assert hasher.cache_size() == 1

    def test_long_lived_hasher_can_stale_hit_after_id_reuse(self) -> None:
        """Scenario: one hasher reused across short-lived expressions; expected no stale hits."""
        hasher = pysymex.core.solver.constraints.ConstraintHasher()
        stale_hits = 0
        for i in range(50_000):
            expr = z3.Int(f"v_{i}") == i
            cached = hasher.hash_expr(expr)
            if cached != expr.hash():
                stale_hits += 1
        assert stale_hits == 0
