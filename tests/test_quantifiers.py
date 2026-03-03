"""
Tests for Phase 21: Quantifier Support.

Tests forall/exists quantifiers in contracts.
"""

import pytest

import z3

from pysymex.contracts.quantifiers import (
    QuantifierKind,
    QuantifierVar,
    BoundSpec,
    Quantifier,
    QuantifierParser,
    parse_condition_to_z3,
    ConditionTranslator,
    forall,
    exists,
    exists_unique,
    QuantifierInstantiator,
    QuantifierVerifier,
    extract_quantifiers,
    replace_quantifiers_with_z3,
)


class TestQuantifierVar:
    """Tests for QuantifierVar."""

    def test_create_int_var(self):
        """Create an integer quantifier variable."""

        var = QuantifierVar(name="i", sort=z3.IntSort())

        assert var.name == "i"

        assert var.sort == z3.IntSort()

        assert isinstance(var.z3_var, z3.ArithRef)

    def test_create_bool_var(self):
        """Create a boolean quantifier variable."""

        var = QuantifierVar(name="b", sort=z3.BoolSort())

        assert var.name == "b"

        assert isinstance(var.z3_var, z3.BoolRef)

    def test_create_real_var(self):
        """Create a real quantifier variable."""

        var = QuantifierVar(name="r", sort=z3.RealSort())

        assert var.name == "r"


class TestBoundSpec:
    """Tests for BoundSpec."""

    def test_lower_inclusive(self):
        """Lower bound inclusive."""

        bound = BoundSpec(lower=z3.IntVal(0), lower_inclusive=True)

        i = z3.Int("i")

        constraint = bound.to_constraint(i)

        solver = z3.Solver()

        solver.add(constraint)

        solver.add(i == 0)

        assert solver.check() == z3.sat

    def test_lower_exclusive(self):
        """Lower bound exclusive."""

        bound = BoundSpec(lower=z3.IntVal(0), lower_inclusive=False)

        i = z3.Int("i")

        constraint = bound.to_constraint(i)

        solver = z3.Solver()

        solver.add(constraint)

        solver.add(i == 0)

        assert solver.check() == z3.unsat

    def test_upper_exclusive(self):
        """Upper bound exclusive (default)."""

        bound = BoundSpec(upper=z3.IntVal(10), upper_inclusive=False)

        i = z3.Int("i")

        constraint = bound.to_constraint(i)

        solver = z3.Solver()

        solver.add(constraint)

        solver.add(i == 10)

        assert solver.check() == z3.unsat

    def test_upper_inclusive(self):
        """Upper bound inclusive."""

        bound = BoundSpec(upper=z3.IntVal(10), upper_inclusive=True)

        i = z3.Int("i")

        constraint = bound.to_constraint(i)

        solver = z3.Solver()

        solver.add(constraint)

        solver.add(i == 10)

        assert solver.check() == z3.sat

    def test_range_bound(self):
        """Combined lower and upper bound."""

        bound = BoundSpec(
            lower=z3.IntVal(0),
            upper=z3.IntVal(10),
            lower_inclusive=True,
            upper_inclusive=False,
        )

        i = z3.Int("i")

        constraint = bound.to_constraint(i)

        solver = z3.Solver()

        solver.add(constraint)

        solver.add(i == 5)

        assert solver.check() == z3.sat

        solver2 = z3.Solver()

        solver2.add(constraint)

        solver2.add(i == -1)

        assert solver2.check() == z3.unsat


class TestQuantifier:
    """Tests for Quantifier class."""

    def test_forall_to_z3(self):
        """Convert forall to Z3."""

        var = QuantifierVar(name="i", sort=z3.IntSort())

        bound = BoundSpec(
            lower=z3.IntVal(0),
            upper=z3.IntVal(10),
        )

        body = var.z3_var >= 0

        q = Quantifier(
            kind=QuantifierKind.FORALL,
            variables=[var],
            bounds=[bound],
            body=body,
        )

        z3_expr = q.to_z3()

        assert z3.is_quantifier(z3_expr)

    def test_exists_to_z3(self):
        """Convert exists to Z3."""

        var = QuantifierVar(name="i", sort=z3.IntSort())

        bound = BoundSpec(
            lower=z3.IntVal(0),
            upper=z3.IntVal(10),
        )

        body = var.z3_var == 5

        q = Quantifier(
            kind=QuantifierKind.EXISTS,
            variables=[var],
            bounds=[bound],
            body=body,
        )

        z3_expr = q.to_z3()

        solver = z3.Solver()

        solver.add(z3_expr)

        assert solver.check() == z3.sat

    def test_forall_all_positive(self):
        """Forall: all elements positive."""

        var = QuantifierVar(name="i", sort=z3.IntSort())

        bound = BoundSpec(lower=z3.IntVal(1), upper=z3.IntVal(10))

        body = var.z3_var > 0

        q = Quantifier(
            kind=QuantifierKind.FORALL,
            variables=[var],
            bounds=[bound],
            body=body,
        )

        solver = z3.Solver()

        solver.add(z3.Not(q.to_z3()))

        assert solver.check() == z3.unsat


class TestQuantifierParser:
    """Tests for QuantifierParser."""

    def test_parse_forall_basic(self):
        """Parse basic forall."""

        parser = QuantifierParser()

        q = parser.parse("forall(i, 0 <= i < 10, i >= 0)")

        assert q is not None

        assert q.kind == QuantifierKind.FORALL

        assert len(q.variables) == 1

        assert q.variables[0].name == "i"

    def test_parse_exists_basic(self):
        """Parse basic exists."""

        parser = QuantifierParser()

        q = parser.parse("exists(i, 0 <= i < 10, i == 5)")

        assert q is not None

        assert q.kind == QuantifierKind.EXISTS

    def test_parse_with_len(self):
        """Parse with len() in bounds."""

        parser = QuantifierParser(context={"x": z3.Array("x", z3.IntSort(), z3.IntSort())})

        q = parser.parse("forall(i, 0 <= i < len(x), x[i] >= 0)")

        assert q is not None

        assert q.kind == QuantifierKind.FORALL


class TestConditionParsing:
    """Tests for condition parsing."""

    def test_comparison(self):
        """Parse comparison."""

        x = z3.Int("x")

        result = parse_condition_to_z3("x > 0", {"x": x})

        solver = z3.Solver()

        solver.add(result)

        solver.add(x == 5)

        assert solver.check() == z3.sat

    def test_chained_comparison(self):
        """Parse chained comparison."""

        x = z3.Int("x")

        result = parse_condition_to_z3("0 <= x < 10", {"x": x})

        solver = z3.Solver()

        solver.add(result)

        solver.add(x == 5)

        assert solver.check() == z3.sat

    def test_boolean_and(self):
        """Parse boolean and."""

        x = z3.Int("x")

        y = z3.Int("y")

        result = parse_condition_to_z3("x > 0 and y > 0", {"x": x, "y": y})

        solver = z3.Solver()

        solver.add(result)

        solver.add(x == 1, y == 1)

        assert solver.check() == z3.sat

    def test_boolean_or(self):
        """Parse boolean or."""

        x = z3.Int("x")

        result = parse_condition_to_z3("x < 0 or x > 10", {"x": x})

        solver = z3.Solver()

        solver.add(result)

        solver.add(x == 5)

        assert solver.check() == z3.unsat

    def test_not(self):
        """Parse not."""

        x = z3.Int("x")

        result = parse_condition_to_z3("not x == 0", {"x": x})

        solver = z3.Solver()

        solver.add(result)

        solver.add(x == 0)

        assert solver.check() == z3.unsat

    def test_arithmetic(self):
        """Parse arithmetic."""

        x = z3.Int("x")

        y = z3.Int("y")

        result = parse_condition_to_z3("x + y == 10", {"x": x, "y": y})

        solver = z3.Solver()

        solver.add(result)

        solver.add(x == 3, y == 7)

        assert solver.check() == z3.sat


class TestHelperFunctions:
    """Tests for forall/exists helper functions."""

    def test_forall_tuple_range(self):
        """forall with tuple range."""

        q = forall("i", (0, 10), "i >= 0")

        assert q is not None

        assert q.kind == QuantifierKind.FORALL

    def test_exists_tuple_range(self):
        """exists with tuple range."""

        q = exists("i", (0, 10), "i == 5")

        assert q is not None

        assert q.kind == QuantifierKind.EXISTS

    def test_forall_string_range(self):
        """forall with string range."""

        q = forall("i", "0 <= i < 10", "i > -1")

        assert q is not None

        assert q.kind == QuantifierKind.FORALL


class TestInstantiation:
    """Tests for quantifier instantiation."""

    def test_instantiate_bounded(self):
        """Instantiate bounded quantifier."""

        var = QuantifierVar(name="i", sort=z3.IntSort())

        bound = BoundSpec(
            lower=z3.IntVal(0),
            upper=z3.IntVal(5),
        )

        body = var.z3_var >= 0

        q = Quantifier(
            kind=QuantifierKind.FORALL,
            variables=[var],
            bounds=[bound],
            body=body,
        )

        instantiator = QuantifierInstantiator()

        solver = z3.Solver()

        instances = instantiator.instantiate_bounded(q, solver)

        assert len(instances) == 5


class TestVerification:
    """Tests for quantifier verification."""

    def test_verify_valid_forall(self):
        """Verify valid forall."""

        var = QuantifierVar(name="i", sort=z3.IntSort())

        bound = BoundSpec(lower=z3.IntVal(1), upper=z3.IntVal(10))

        body = var.z3_var > 0

        q = Quantifier(
            kind=QuantifierKind.FORALL,
            variables=[var],
            bounds=[bound],
            body=body,
        )

        verifier = QuantifierVerifier()

        valid, counter = verifier.verify_forall(q)

        assert valid is True

        assert counter is None

    def test_verify_invalid_forall(self):
        """Verify invalid forall."""

        var = QuantifierVar(name="i", sort=z3.IntSort())

        bound = BoundSpec(lower=z3.IntVal(0), upper=z3.IntVal(10))

        body = var.z3_var > 5

        q = Quantifier(
            kind=QuantifierKind.FORALL,
            variables=[var],
            bounds=[bound],
            body=body,
        )

        verifier = QuantifierVerifier()

        valid, counter = verifier.verify_forall(q)

        assert valid is False

        assert counter is not None

    def test_verify_satisfiable_exists(self):
        """Verify satisfiable exists."""

        var = QuantifierVar(name="i", sort=z3.IntSort())

        bound = BoundSpec(lower=z3.IntVal(0), upper=z3.IntVal(10))

        body = var.z3_var == 5

        q = Quantifier(
            kind=QuantifierKind.EXISTS,
            variables=[var],
            bounds=[bound],
            body=body,
        )

        verifier = QuantifierVerifier()

        sat, witness = verifier.verify_exists(q)

        assert sat is True

        assert witness is not None

    def test_verify_unsatisfiable_exists(self):
        """Verify unsatisfiable exists."""

        var = QuantifierVar(name="i", sort=z3.IntSort())

        bound = BoundSpec(lower=z3.IntVal(0), upper=z3.IntVal(10))

        body = var.z3_var == 100

        q = Quantifier(
            kind=QuantifierKind.EXISTS,
            variables=[var],
            bounds=[bound],
            body=body,
        )

        verifier = QuantifierVerifier()

        sat, witness = verifier.verify_exists(q)

        assert sat is False

        assert witness is None


class TestIntegration:
    """Integration tests for quantifiers."""

    def test_extract_quantifiers(self):
        """Extract quantifiers from contract."""

        contract = "forall(i, 0 <= i < len(x), x[i] >= 0) and result > 0"

        quantifiers = extract_quantifiers(contract)

        assert len(quantifiers) == 1

        assert quantifiers[0].kind == QuantifierKind.FORALL

    def test_extract_multiple_quantifiers(self):
        """Extract multiple quantifiers."""

        contract = "forall(i, 0 <= i < n, x[i] > 0) and exists(j, 0 <= j < n, x[j] == max)"

        quantifiers = extract_quantifiers(contract)

        assert len(quantifiers) == 2

    def test_sorted_array_property(self):
        """Verify sorted array property."""

        i = z3.Int("i")

        n = z3.Int("n")

        arr = z3.Array("arr", z3.IntSort(), z3.IntSort())

        bound = BoundSpec(lower=z3.IntVal(0), upper=n - 1)

        body = z3.Select(arr, i) <= z3.Select(arr, i + 1)

        var = QuantifierVar(name="i", sort=z3.IntSort())

        var.z3_var = i

        q = Quantifier(
            kind=QuantifierKind.FORALL,
            variables=[var],
            bounds=[bound],
            body=body,
        )

        z3_expr = q.to_z3()

        assert z3.is_quantifier(z3_expr)

    def test_all_elements_positive(self):
        """Verify all elements positive."""

        i = z3.Int("i")

        length = z3.Int("length")

        arr = z3.Array("arr", z3.IntSort(), z3.IntSort())

        var = QuantifierVar(name="i", sort=z3.IntSort())

        var.z3_var = i

        bound = BoundSpec(lower=z3.IntVal(0), upper=length)

        body = z3.Select(arr, i) >= 0

        q = Quantifier(
            kind=QuantifierKind.FORALL,
            variables=[var],
            bounds=[bound],
            body=body,
        )

        solver = z3.Solver()

        solver.add(q.to_z3())

        solver.add(length == 3)

        assert solver.check() == z3.sat

    def test_element_exists_in_array(self):
        """Verify element exists in array."""

        i = z3.Int("i")

        length = z3.Int("length")

        arr = z3.Array("arr", z3.IntSort(), z3.IntSort())

        target = z3.Int("target")

        var = QuantifierVar(name="i", sort=z3.IntSort())

        var.z3_var = i

        bound = BoundSpec(lower=z3.IntVal(0), upper=length)

        body = z3.Select(arr, i) == target

        q = Quantifier(
            kind=QuantifierKind.EXISTS,
            variables=[var],
            bounds=[bound],
            body=body,
        )

        solver = z3.Solver()

        solver.add(length == 3)

        solver.add(target == 42)

        solver.add(z3.Store(arr, z3.IntVal(1), z3.IntVal(42)) == arr)

        solver.add(q.to_z3())

        result = solver.check()

        assert result in (z3.sat, z3.unknown)


class TestUseCases:
    """Tests for real-world use cases."""

    def test_abs_all_positive(self):
        """
        @ensures('forall(i, 0 <= i < len(result), result[i] >= 0)')
        def abs_all(items: List[int]) -> List[int]:
            return [abs(x) for x in items]
        """

        i = z3.Int("i")

        result = z3.Array("result", z3.IntSort(), z3.IntSort())

        length = z3.Int("length")

        var = QuantifierVar(name="i", sort=z3.IntSort())

        var.z3_var = i

        bound = BoundSpec(lower=z3.IntVal(0), upper=length)

        body = z3.Select(result, i) >= 0

        q = Quantifier(
            kind=QuantifierKind.FORALL,
            variables=[var],
            bounds=[bound],
            body=body,
        )

        z3_expr = q.to_z3()

        assert z3.is_quantifier(z3_expr)

    def test_find_precondition(self):
        """
        @requires('exists(i, 0 <= i < len(items), items[i] == target)')
        def find(items: List[int], target: int) -> int:
            return items.index(target)
        """

        i = z3.Int("i")

        items = z3.Array("items", z3.IntSort(), z3.IntSort())

        target = z3.Int("target")

        length = z3.Int("length")

        var = QuantifierVar(name="i", sort=z3.IntSort())

        var.z3_var = i

        bound = BoundSpec(lower=z3.IntVal(0), upper=length)

        body = z3.Select(items, i) == target

        q = Quantifier(
            kind=QuantifierKind.EXISTS,
            variables=[var],
            bounds=[bound],
            body=body,
        )

        z3_expr = q.to_z3()

        assert q.kind == QuantifierKind.EXISTS

    def test_binary_search_invariant(self):
        """Binary search loop invariant."""

        i = z3.Int("i")

        arr = z3.Array("arr", z3.IntSort(), z3.IntSort())

        target = z3.Int("target")

        low = z3.Int("low")

        high = z3.Int("high")

        var = QuantifierVar(name="i", sort=z3.IntSort())

        var.z3_var = i

        bound1 = BoundSpec(lower=z3.IntVal(0), upper=low)

        body1 = z3.Select(arr, i) < target

        q1 = Quantifier(
            kind=QuantifierKind.FORALL,
            variables=[var],
            bounds=[bound1],
            body=body1,
        )

        bound2 = BoundSpec(lower=high, upper=z3.Int("length"))

        body2 = z3.Select(arr, i) > target

        var2 = QuantifierVar(name="j", sort=z3.IntSort())

        q2 = Quantifier(
            kind=QuantifierKind.FORALL,
            variables=[var2],
            bounds=[bound2],
            body=z3.Select(arr, var2.z3_var) > target,
        )

        assert q1.kind == QuantifierKind.FORALL

        assert q2.kind == QuantifierKind.FORALL
