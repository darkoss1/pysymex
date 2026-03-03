"""Comprehensive edge case tests for symbolic execution.

Tests for:
- Division edge cases
- Overflow scenarios
- Empty collection handling
- Null/None propagation
- Boundary conditions
"""

import pytest

import z3

from unittest.mock import MagicMock


from pysymex.core.state import VMState

from pysymex.core.solver import is_satisfiable, get_model

from pysymex.api import analyze


class TestDivisionEdgeCases:
    """Tests for division edge cases."""

    def test_division_by_zero_detected(self):
        """Test that division by zero is detected."""

        def divide(x, y):
            return x / y

        result = analyze(divide, {"x": "int", "y": "int"})

        assert result.has_issues()

    def test_division_by_one_safe(self):
        """Test that division by 1 is safe."""

        def divide_by_one(x):
            return x / 1

        result = analyze(divide_by_one, {"x": "int"})

        div_issues = [i for i in result.issues if "DIVISION" in str(i.kind)]

        assert len(div_issues) == 0

    def test_division_with_guard(self):
        """Test that guarded division is safe."""

        def safe_divide(x, y):
            if y != 0:
                return x / y

            return 0

        result = analyze(safe_divide, {"x": "int", "y": "int"})

        div_issues = [i for i in result.issues if "DIVISION" in str(i.kind)]

        assert len(div_issues) == 0

    def test_modulo_by_zero(self):
        """Test modulo by zero detection."""

        def modulo(x, y):
            return x % y

        result = analyze(modulo, {"x": "int", "y": "int"})

        assert result.has_issues()

    def test_floor_division_by_zero(self):
        """Test floor division by zero."""

        def floor_div(x, y):
            return x // y

        result = analyze(floor_div, {"x": "int", "y": "int"})

        assert result.has_issues()

    def test_division_with_negative(self):
        """Test division with negative values."""

        def divide_neg(x, y):
            if y < 0:
                return x / y

            return 0

        result = analyze(divide_neg, {"x": "int", "y": "int"})

        div_issues = [i for i in result.issues if "DIVISION" in str(i.kind)]

        assert len(div_issues) == 0

    def test_division_with_positive(self):
        """Test division with positive values."""

        def divide_pos(x, y):
            if y > 0:
                return x / y

            return 0

        result = analyze(divide_pos, {"x": "int", "y": "int"})

        div_issues = [i for i in result.issues if "DIVISION" in str(i.kind)]

        assert len(div_issues) == 0

    def test_chained_division(self):
        """Test chained division operations."""

        def chain(a, b, c):
            return a / b / c

        result = analyze(chain, {"a": "int", "b": "int", "c": "int"})

        assert result.has_issues()

    def test_division_in_expression(self):
        """Test division within complex expression."""

        def expr(x, y, z):
            return (x + y) / (z - 1)

        result = analyze(expr, {"x": "int", "y": "int", "z": "int"})

        assert result.has_issues()


class TestZ3SymbolicEdgeCases:
    """Tests for Z3 symbolic value operations."""

    def test_z3_int_creation(self):
        """Test creating z3 int."""

        x = z3.Int("x")

        assert x is not None

    def test_z3_negation(self):
        """Test z3 negation."""

        x = z3.Int("x")

        neg_x = -x

        assert neg_x is not None

    def test_z3_addition(self):
        """Test z3 addition."""

        x = z3.Int("x")

        y = z3.Int("y")

        result = x + y

        assert result is not None

    def test_z3_comparison(self):
        """Test z3 comparison."""

        x = z3.Int("x")

        result = x > 0

        assert result is not None

    def test_z3_with_concrete(self):
        """Test z3 with concrete value."""

        x = z3.Int("x")

        result = x + 5

        assert result is not None

    def test_z3_bool_creation(self):
        """Test creating z3 bool."""

        b = z3.Bool("flag")

        assert b is not None

    def test_z3_real_creation(self):
        """Test creating z3 real."""

        r = z3.Real("r")

        assert r is not None


class TestCollectionEdgeCases:
    """Tests for collection edge cases."""

    def test_empty_list_index(self):
        """Test indexing empty list."""

        def index_empty(lst):
            return lst[0]

        result = analyze(index_empty, {"lst": "list"})

        assert result is not None

    def test_negative_index(self):
        """Test negative indexing."""

        def neg_index(lst):
            return lst[-1]

        result = analyze(neg_index, {"lst": "list"})

        assert result is not None

    def test_dict_missing_key(self):
        """Test dictionary missing key access."""

        def get_key(d):
            return d["missing"]

        result = analyze(get_key, {"d": "dict"})

        assert result is not None

    def test_list_append(self):
        """Test list append."""

        def append_list(lst, val):
            lst.append(val)

            return lst

        result = analyze(append_list, {"lst": "list", "val": "int"})

        assert result is not None

    def test_list_len(self):
        """Test list length."""

        def get_len(lst):
            return len(lst)

        result = analyze(get_len, {"lst": "list"})

        assert result is not None


class TestOverflowEdgeCases:
    """Tests for overflow scenarios."""

    def test_large_int_addition(self):
        """Test adding large integers."""

        x = z3.Int("x")

        y = z3.Int("y")

        solver = z3.Solver()

        solver.add(x == 10**100)

        solver.add(y == 10**100)

        solver.add(x + y == 2 * 10**100)

        assert solver.check() == z3.sat

    def test_multiplication_operation(self):
        """Test multiplication operation."""

        def multiply(x, y):
            result = x * y

            return result

        result = analyze(multiply, {"x": "int", "y": "int"})

        assert result is not None

    def test_power_operation(self):
        """Test power operation."""

        def power(base, exp):
            return base**exp

        result = analyze(power, {"base": "int", "exp": "int"})

        assert result is not None


class TestNonePropagation:
    """Tests for None propagation."""

    def test_none_guard(self):
        """Test None guard pattern."""

        def access_attr(obj):
            if obj is not None:
                return len(obj)

            return 0

        result = analyze(access_attr, {"obj": "list"})

        assert result is not None

    def test_none_return(self):
        """Test returning None."""

        def maybe_return(x):
            if x > 0:
                return x

            return None

        result = analyze(maybe_return, {"x": "int"})

        assert result is not None


class TestBoundaryConditions:
    """Tests for boundary conditions."""

    def test_list_boundary_access(self):
        """Test list access at boundaries."""

        def boundary_access(lst, i):
            if 0 <= i < len(lst):
                return lst[i]

            return -1

        result = analyze(boundary_access, {"lst": "list", "i": "int"})

        assert result is not None

    def test_zero_boundary(self):
        """Test zero as boundary value."""

        def zero_check(x):
            if x >= 0:
                return 100 / x

            return 0

        result = analyze(zero_check, {"x": "int"})

        assert result.has_issues()

    def test_negative_boundary(self):
        """Test negative boundary handling."""

        def neg_boundary(x):
            if x > -10:
                return 1 / (x + 10)

            return 0

        result = analyze(neg_boundary, {"x": "int"})

        div_issues = [i for i in result.issues if "DIVISION" in str(i.kind)]

        assert len(div_issues) == 0


class TestStringEdgeCases:
    """Tests for string edge cases."""

    def test_empty_string_handling(self):
        """Test empty string handling."""

        def check_empty(s):
            if len(s) > 0:
                return s[0]

            return ""

        result = analyze(check_empty, {"s": "str"})

        assert result is not None

    def test_string_concatenation(self):
        """Test string concatenation."""

        def concat(a, b):
            return a + b

        result = analyze(concat, {"a": "str", "b": "str"})

        assert result is not None


class TestControlFlowEdgeCases:
    """Tests for control flow edge cases."""

    def test_deeply_nested_conditions(self):
        """Test deeply nested conditions."""

        def nested(a, b, c, d):
            if a > 0:
                if b > 0:
                    if c > 0:
                        if d > 0:
                            return a / b / c / d

            return 0

        result = analyze(nested, {"a": "int", "b": "int", "c": "int", "d": "int"})

        div_issues = [i for i in result.issues if "DIVISION" in str(i.kind)]

        assert len(div_issues) == 0

    def test_short_circuit_evaluation(self):
        """Test short-circuit evaluation."""

        def short_circuit(x, y):
            if x != 0 and y / x > 0:
                return True

            return False

        result = analyze(short_circuit, {"x": "int", "y": "int"})

        assert result is not None

    def test_multiple_return_paths(self):
        """Test multiple return paths."""

        def multi_return(x, y):
            if x < 0:
                return -1

            if x == 0:
                return 0

            if y == 0:
                return x

            return x / y

        result = analyze(multi_return, {"x": "int", "y": "int"})

        div_issues = [i for i in result.issues if "DIVISION" in str(i.kind)]

        assert len(div_issues) == 0


class TestSolverEdgeCases:
    """Tests for solver edge cases."""

    def test_satisfiable_simple(self):
        """Test simple satisfiable constraint."""

        x = z3.Int("x")

        assert is_satisfiable([x > 0])

    def test_unsatisfiable_contradiction(self):
        """Test contradiction is unsatisfiable."""

        x = z3.Int("x")

        assert not is_satisfiable([x > 0, x < 0])

    def test_get_model_simple(self):
        """Test getting a model."""

        x = z3.Int("x")

        model = get_model([x == 42])

        assert model is not None

    def test_complex_constraints(self):
        """Test complex constraint set."""

        x = z3.Int("x")

        y = z3.Int("y")

        z_var = z3.Int("z")

        constraints = [
            x > 0,
            y > x,
            z_var > y,
            z_var < 100,
        ]

        assert is_satisfiable(constraints)

    def test_equality_constraint(self):
        """Test equality constraints."""

        x = z3.Int("x")

        y = z3.Int("y")

        constraints = [x == y, x == 5]

        model = get_model(constraints)

        assert model is not None


class TestTypeHandlingEdgeCases:
    """Tests for type handling edge cases."""

    def test_int_operations(self):
        """Test int operations."""

        def int_ops(x):
            return x * 2 + 1

        result = analyze(int_ops, {"x": "int"})

        assert result is not None

    def test_bool_operations(self):
        """Test bool operations."""

        def bool_ops(flag):
            return not flag

        result = analyze(bool_ops, {"flag": "bool"})

        assert result is not None

    def test_mixed_arithmetic(self):
        """Test mixed type arithmetic."""

        def mixed(x, y):
            return x + y * 2

        result = analyze(mixed, {"x": "int", "y": "int"})

        assert result is not None
