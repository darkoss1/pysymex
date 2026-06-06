import pysymex.core.solver.unsat
import pytest
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


def test_extract_unsat_core_translates_cross_context_constraints() -> None:
    """Scenario: cross-context contradiction; expected core extraction still succeeds."""
    ctx = z3.Context()
    x = z3.Int("x_cross_context_unsat_core", ctx=ctx)

    core = pysymex.core.solver.unsat.extract_unsat_core([x > 0, x <= 0])

    assert core is not None
    assert set(core.core_indices) == {0, 1}


def test_extract_unsat_core_check_failure_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """Scenario: solver check fails; expected no UNSAT core evidence."""
    x = z3.Int("x_unsat_core_check_failure")

    def raising_check(self: z3.Solver, *assumptions: z3.BoolRef) -> z3.CheckSatResult:
        _ = self
        _ = assumptions
        raise z3.Z3Exception("forced unsat-core check failure")

    monkeypatch.setattr(z3.Solver, "check", raising_check)

    assert pysymex.core.solver.unsat.extract_unsat_core([x > 0, x <= 0]) is None


def test_extract_unsat_core_extraction_failure_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scenario: solver unsat_core fails; expected no UNSAT core evidence."""
    x = z3.Int("x_unsat_core_extraction_failure")

    def raising_unsat_core(self: z3.Solver) -> list[z3.BoolRef]:
        _ = self
        raise z3.Z3Exception("forced unsat-core extraction failure")

    monkeypatch.setattr(z3.Solver, "unsat_core", raising_unsat_core)

    assert pysymex.core.solver.unsat.extract_unsat_core([x > 0, x <= 0]) is None


def test_core_indicator_names_are_deterministic(monkeypatch: pytest.MonkeyPatch) -> None:
    """Scenario: assumption names should not depend on Python object identity."""
    original_bool = z3.Bool
    first_names: list[str] = []
    second_names: list[str] = []

    def capture_first(name: str, ctx: z3.Context | None = None) -> z3.BoolRef:
        first_names.append(name)
        return original_bool(name, ctx=ctx)

    def capture_second(name: str, ctx: z3.Context | None = None) -> z3.BoolRef:
        second_names.append(name)
        return original_bool(name, ctx=ctx)

    x = z3.Int("x_core_name")
    monkeypatch.setattr(z3, "Bool", capture_first)
    first = pysymex.core.solver.unsat.extract_unsat_core([x > 0, x <= 0])

    monkeypatch.setattr(z3, "Bool", capture_second)
    second = pysymex.core.solver.unsat.extract_unsat_core([x > 0, x <= 0])

    assert first is not None
    assert second is not None
    assert first_names == second_names
    assert len(first_names) == 2
    assert first_names[0] != first_names[1]
    assert all(name.startswith("_pysymex_core_ind_") for name in first_names)


def test_prune_with_core() -> None:
    """Scenario: prune by selected indices; expected only indexed constraints kept."""
    constraints = [z3.Bool("a"), z3.Bool("b"), z3.Bool("c")]
    core = pysymex.core.solver.unsat.UnsatCoreResult([constraints[1]], [1], 3)
    assert pysymex.core.solver.unsat.prune_with_core(constraints, core) == [constraints[1]]
