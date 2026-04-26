import pysymex.core.solver.constraints
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


def test_simplify_constraints() -> None:
    """Scenario: constraints include true literal; expected true removed after simplify."""
    x = z3.Int("x")
    simplified = pysymex.core.solver.constraints.simplify_constraints([z3.BoolVal(True), x > 0])
    assert len(simplified) == 1


def test_quick_contradiction_check() -> None:
    """Scenario: direct contradiction pair c and not c; expected contradiction detected."""
    c = z3.Bool("c")
    assert pysymex.core.solver.constraints.quick_contradiction_check([c, z3.Not(c)]) is True


def test_remove_subsumed() -> None:
    """Scenario: duplicate structural constraints; expected deduplicated output."""
    c = z3.Bool("d")
    assert pysymex.core.solver.constraints.remove_subsumed([c, c]) == [c]
