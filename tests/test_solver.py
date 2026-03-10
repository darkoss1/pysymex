"""Unit tests for ShadowSolver."""

import pytest
import z3

from pysymex.core.solver import ShadowSolver, get_model, is_satisfiable


class TestShadowSolver:
    """Tests for ShadowSolver class."""

    def test_create_solver(self):
        """Test creating solver instance."""
        solver = ShadowSolver()

        assert solver is not None

    def test_is_satisfiable_true(self):
        """Test satisfiable constraints."""
        x = z3.Int("x")
        constraints = [x > 0, x < 10]

        result = is_satisfiable(constraints)

        assert result == True

    def test_is_satisfiable_false(self):
        """Test unsatisfiable constraints."""
        x = z3.Int("x")
        constraints = [x > 10, x < 5]

        result = is_satisfiable(constraints)

        assert result == False

    def test_get_model(self):
        """Test model extraction."""
        x = z3.Int("x")
        constraints = [x == 42]

        model = get_model(constraints)

        assert model is not None
        assert model.eval(x).as_long() == 42

    def test_empty_constraints(self):
        """Test empty constraints are satisfiable."""
        result = is_satisfiable([])

        assert result == True

    def test_boolean_constraints(self):
        """Test boolean constraints."""
        a = z3.Bool("a")
        b = z3.Bool("b")

        constraints = [z3.Or(a, b), z3.Not(a)]

        assert is_satisfiable(constraints)

        model = get_model(constraints)
        assert z3.is_true(model.eval(b))  # type: ignore[reportOptionalMemberAccess]

    def test_string_constraints(self):
        """Test string constraint handling."""
        s = z3.String("s")

        constraints = [z3.Length(s) > 0, z3.Length(s) < 10]

        assert is_satisfiable(constraints)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
