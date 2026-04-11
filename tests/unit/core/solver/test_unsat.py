import pysymex.core.solver.unsat
import z3

class TestUnsatCoreResult:
    """Test suite for pysymex.core.solver.unsat.UnsatCoreResult."""
    def test_reduction_ratio(self) -> None:
        """Scenario: one core constraint out of two total; expected 0.5 reduction ratio."""
        result = pysymex.core.solver.unsat.UnsatCoreResult([z3.BoolVal(False)], [0], 2)
        assert result.reduction_ratio == 0.5


def test_extract_unsat_core() -> None:
    """Scenario: contradictory constraints; expected UNSAT core extraction result."""
    x = z3.Int("x")
    core = pysymex.core.solver.unsat.extract_unsat_core([x > 0, x <= 0])
    assert core is not None


def test_prune_with_core() -> None:
    """Scenario: prune by selected indices; expected only indexed constraints kept."""
    constraints = [z3.Bool("a"), z3.Bool("b"), z3.Bool("c")]
    core = pysymex.core.solver.unsat.UnsatCoreResult([constraints[1]], [1], 3)
    assert pysymex.core.solver.unsat.prune_with_core(constraints, core) == [constraints[1]]
