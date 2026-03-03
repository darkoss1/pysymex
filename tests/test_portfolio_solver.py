"""Tests for PortfolioSolver (parallel tactic execution)."""

import pytest

import z3


from pysymex.core.solver import PortfolioSolver, SolverResult


class TestPortfolioSolverBasic:
    """Basic portfolio solver functionality."""

    def test_create_solver(self):
        solver = PortfolioSolver()

        assert solver._timeout_ms == 10000

    def test_create_with_params(self):
        solver = PortfolioSolver(timeout_ms=5000, fast_timeout_ms=50, max_workers=2)

        assert solver._timeout_ms == 5000

        assert solver._fast_timeout_ms == 50

        assert solver._max_workers == 2

    def test_tactics_defined(self):
        assert len(PortfolioSolver.TACTICS) > 0

        assert "smt" in PortfolioSolver.TACTICS


class TestPortfolioSerialization:
    """Constraint serialization for cross-process transfer."""

    def test_serialize_simple(self):
        solver = PortfolioSolver()

        x = z3.Int("x")

        smt_str = solver._serialize_constraints([x > 0])

        assert smt_str is not None

        assert isinstance(smt_str, str)

    def test_serialize_complex(self):
        solver = PortfolioSolver()

        x, y = z3.Ints("x y")

        constraints = [x + y > 10, x > 0, y > 0, x * y < 100]

        smt_str = solver._serialize_constraints(constraints)

        assert smt_str is not None

    def test_serialize_empty(self):
        solver = PortfolioSolver()

        smt_str = solver._serialize_constraints([])

        assert smt_str is not None


class TestPortfolioCheckHard:
    """Solving hard queries with parallel tactics."""

    def test_sat_query(self):
        solver = PortfolioSolver(timeout_ms=5000, max_workers=2)

        x = z3.Int("x")

        result = solver.check_hard([x > 0, x < 100])

        assert isinstance(result, SolverResult)

    def test_unsat_query(self):
        solver = PortfolioSolver(timeout_ms=5000, max_workers=2)

        x = z3.Int("x")

        result = solver.check_hard([x > 0, x < 0])

        assert isinstance(result, SolverResult)

        if not result.is_unknown:
            assert result.is_unsat

    def test_returns_solver_result_type(self):
        solver = PortfolioSolver(timeout_ms=2000, max_workers=1)

        x = z3.Int("x")

        result = solver.check_hard([x == 42])

        assert isinstance(result, SolverResult)


class TestSolverResult:
    """SolverResult dataclass."""

    def test_sat_factory(self):
        model = None

        result = SolverResult(is_sat=True, is_unsat=False, is_unknown=False)

        assert result.is_sat

        assert not result.is_unsat

        assert not result.is_unknown

    def test_unsat_factory(self):
        result = SolverResult.unsat()

        assert not result.is_sat

        assert result.is_unsat

        assert not result.is_unknown

    def test_unknown_factory(self):
        result = SolverResult.unknown()

        assert not result.is_sat

        assert not result.is_unsat

        assert result.is_unknown
