"""
Tests for Phase 22: Abstract Interpretation Layer.

Tests abstract domains: interval, sign, parity, null.
"""

import pytest

import z3

from pysymex.analysis.abstract.domains import (
    Interval,
    Sign,
    SignValue,
    Parity,
    ParityValue,
    Null,
    NullValue,
    ProductDomain,
    AbstractState,
    AbstractInterpreter,
)


class TestInterval:
    """Tests for Interval abstract domain."""

    def test_from_concrete(self):
        """Create singleton interval."""

        i = Interval.from_concrete(5)

        assert i.lo == 5

        assert i.hi == 5

        assert i.is_constant()

    def test_top(self):
        """Top is unbounded."""

        i = Interval.top()

        assert i.is_top()

        assert i.lo is None

        assert i.hi is None

    def test_bottom(self):
        """Bottom is empty."""

        i = Interval.bottom()

        assert i.is_bottom()

    def test_range(self):
        """Bounded interval."""

        i = Interval.range(0, 10)

        assert i.lo == 0

        assert i.hi == 10

        assert i.contains(5)

        assert not i.contains(-1)

        assert not i.contains(11)

    def test_at_least(self):
        """Lower-bounded interval."""

        i = Interval.at_least(0)

        assert i.lo == 0

        assert i.hi is None

        assert i.contains(100)

        assert not i.contains(-1)

    def test_at_most(self):
        """Upper-bounded interval."""

        i = Interval.at_most(10)

        assert i.lo is None

        assert i.hi == 10

        assert i.contains(-100)

        assert not i.contains(11)

    def test_join(self):
        """Join of intervals."""

        i1 = Interval.range(0, 5)

        i2 = Interval.range(3, 10)

        joined = i1.join(i2)

        assert joined.lo == 0

        assert joined.hi == 10

    def test_join_with_bottom(self):
        """Join with bottom."""

        i = Interval.range(0, 10)

        joined = i.join(Interval.bottom())

        assert joined.lo == 0

        assert joined.hi == 10

    def test_meet(self):
        """Meet of intervals."""

        i1 = Interval.range(0, 10)

        i2 = Interval.range(5, 15)

        met = i1.meet(i2)

        assert met.lo == 5

        assert met.hi == 10

    def test_meet_disjoint(self):
        """Meet of disjoint intervals is bottom."""

        i1 = Interval.range(0, 5)

        i2 = Interval.range(10, 15)

        met = i1.meet(i2)

        assert met.is_bottom()

    def test_widen(self):
        """Widening extends bounds."""

        i1 = Interval.range(0, 10)

        i2 = Interval.range(-5, 15)

        widened = i1.widen(i2)

        assert widened.lo is None

        assert widened.hi is None

    def test_add(self):
        """Interval addition."""

        i1 = Interval.range(1, 5)

        i2 = Interval.range(10, 20)

        result = i1 + i2

        assert result.lo == 11

        assert result.hi == 25

    def test_sub(self):
        """Interval subtraction."""

        i1 = Interval.range(10, 20)

        i2 = Interval.range(1, 5)

        result = i1 - i2

        assert result.lo == 5

        assert result.hi == 19

    def test_mul(self):
        """Interval multiplication."""

        i1 = Interval.range(2, 3)

        i2 = Interval.range(4, 5)

        result = i1 * i2

        assert result.lo == 8

        assert result.hi == 15

    def test_neg(self):
        """Interval negation."""

        i = Interval.range(3, 7)

        negated = -i

        assert negated.lo == -7

        assert negated.hi == -3

    def test_to_z3_constraint(self):
        """Convert to Z3 constraint."""

        i = Interval.range(0, 10)

        x = z3.Int("x")

        constraint = i.to_z3_constraint(x)

        solver = z3.Solver()

        solver.add(constraint)

        solver.add(x == 5)

        assert solver.check() == z3.sat

        solver2 = z3.Solver()

        solver2.add(constraint)

        solver2.add(x == 15)

        assert solver2.check() == z3.unsat


class TestSign:
    """Tests for Sign abstract domain."""

    def test_from_concrete_positive(self):
        """Positive value."""

        s = Sign.from_concrete(5)

        assert s.value == SignValue.POS

    def test_from_concrete_negative(self):
        """Negative value."""

        s = Sign.from_concrete(-3)

        assert s.value == SignValue.NEG

    def test_from_concrete_zero(self):
        """Zero value."""

        s = Sign.from_concrete(0)

        assert s.value == SignValue.ZERO

    def test_top(self):
        """Top is unknown."""

        s = Sign.top()

        assert s.is_top()

    def test_bottom(self):
        """Bottom is empty."""

        s = Sign.bottom()

        assert s.is_bottom()

    def test_join_pos_zero(self):
        """Join positive and zero -> non-negative."""

        s1 = Sign.positive()

        s2 = Sign.zero()

        joined = s1.join(s2)

        assert joined.value == SignValue.NON_NEG

    def test_join_neg_zero(self):
        """Join negative and zero -> non-positive."""

        s1 = Sign.negative()

        s2 = Sign.zero()

        joined = s1.join(s2)

        assert joined.value == SignValue.NON_POS

    def test_join_pos_neg(self):
        """Join positive and negative -> non-zero."""

        s1 = Sign.positive()

        s2 = Sign.negative()

        joined = s1.join(s2)

        assert joined.value == SignValue.NON_ZERO

    def test_meet_non_neg_non_pos(self):
        """Meet non-negative and non-positive -> zero."""

        s1 = Sign.non_negative()

        s2 = Sign.non_positive()

        met = s1.meet(s2)

        assert met.value == SignValue.ZERO

    def test_to_z3_constraint(self):
        """Convert to Z3 constraint."""

        s = Sign.positive()

        x = z3.Int("x")

        constraint = s.to_z3_constraint(x)

        solver = z3.Solver()

        solver.add(constraint)

        solver.add(x == 5)

        assert solver.check() == z3.sat

        solver2 = z3.Solver()

        solver2.add(constraint)

        solver2.add(x == -1)

        assert solver2.check() == z3.unsat


class TestParity:
    """Tests for Parity abstract domain."""

    def test_from_concrete_even(self):
        """Even number."""

        p = Parity.from_concrete(4)

        assert p.value == ParityValue.EVEN

    def test_from_concrete_odd(self):
        """Odd number."""

        p = Parity.from_concrete(7)

        assert p.value == ParityValue.ODD

    def test_top(self):
        """Top is unknown parity."""

        p = Parity.top()

        assert p.is_top()

    def test_join_same(self):
        """Join same parity -> same."""

        p1 = Parity.even()

        p2 = Parity.even()

        joined = p1.join(p2)

        assert joined.value == ParityValue.EVEN

    def test_join_different(self):
        """Join different parity -> top."""

        p1 = Parity.even()

        p2 = Parity.odd()

        joined = p1.join(p2)

        assert joined.is_top()

    def test_add_even_even(self):
        """Even + even = even."""

        result = Parity.even() + Parity.even()

        assert result.value == ParityValue.EVEN

    def test_add_odd_odd(self):
        """Odd + odd = even."""

        result = Parity.odd() + Parity.odd()

        assert result.value == ParityValue.EVEN

    def test_add_even_odd(self):
        """Even + odd = odd."""

        result = Parity.even() + Parity.odd()

        assert result.value == ParityValue.ODD

    def test_mul_even_anything(self):
        """Even * anything = even."""

        result = Parity.even() * Parity.odd()

        assert result.value == ParityValue.EVEN

    def test_mul_odd_odd(self):
        """Odd * odd = odd."""

        result = Parity.odd() * Parity.odd()

        assert result.value == ParityValue.ODD

    def test_to_z3_constraint(self):
        """Convert to Z3 constraint."""

        p = Parity.even()

        x = z3.Int("x")

        constraint = p.to_z3_constraint(x)

        solver = z3.Solver()

        solver.add(constraint)

        solver.add(x == 4)

        assert solver.check() == z3.sat

        solver2 = z3.Solver()

        solver2.add(constraint)

        solver2.add(x == 5)

        assert solver2.check() == z3.unsat


class TestNull:
    """Tests for Null abstract domain."""

    def test_from_concrete_null(self):
        """None maps to null."""

        n = Null.from_concrete(None)

        assert n.value == NullValue.NULL

    def test_from_concrete_non_null(self):
        """Non-None maps to non-null."""

        n = Null.from_concrete("hello")

        assert n.value == NullValue.NON_NULL

    def test_is_null(self):
        """Check if definitely null."""

        n = Null.null()

        assert n.is_null()

        assert n.may_be_null()

    def test_is_non_null(self):
        """Check if definitely non-null."""

        n = Null.non_null()

        assert n.is_non_null()

        assert not n.may_be_null()

    def test_top_may_be_null(self):
        """Top may be null."""

        n = Null.top()

        assert n.may_be_null()

    def test_join_null_non_null(self):
        """Join null and non-null -> top."""

        n1 = Null.null()

        n2 = Null.non_null()

        joined = n1.join(n2)

        assert joined.is_top()

    def test_to_z3_constraint(self):
        """Convert to Z3 constraint."""

        n = Null.non_null()

        x = z3.Int("x")

        constraint = n.to_z3_constraint(x)

        solver = z3.Solver()

        solver.add(constraint)

        solver.add(x == 42)

        assert solver.check() == z3.sat

        solver2 = z3.Solver()

        solver2.add(constraint)

        solver2.add(x == 0)

        assert solver2.check() == z3.unsat


class TestProductDomain:
    """Tests for ProductDomain."""

    def test_from_concrete(self):
        """Create from concrete integer."""

        p = ProductDomain.from_concrete(6)

        assert p.interval.lo == 6

        assert p.interval.hi == 6

        assert p.sign.value == SignValue.POS

        assert p.parity.value == ParityValue.EVEN

    def test_join(self):
        """Join product domains."""

        p1 = ProductDomain.from_concrete(2)

        p2 = ProductDomain.from_concrete(4)

        joined = p1.join(p2)

        assert joined.interval.lo == 2

        assert joined.interval.hi == 4

    def test_meet(self):
        """Meet product domains."""

        p1 = ProductDomain(interval=Interval.range(0, 10))

        p2 = ProductDomain(interval=Interval.range(5, 15))

        met = p1.meet(p2)

        assert met.interval.lo == 5

        assert met.interval.hi == 10

    def test_to_z3_constraint(self):
        """Convert to combined Z3 constraint."""

        p = ProductDomain(
            interval=Interval.range(0, 10),
            sign=Sign.positive(),
            parity=Parity.even(),
        )

        x = z3.Int("x")

        constraint = p.to_z3_constraint(x)

        solver = z3.Solver()

        solver.add(constraint)

        solver.add(x == 4)

        assert solver.check() == z3.sat

        solver2 = z3.Solver()

        solver2.add(constraint)

        solver2.add(x == 5)

        assert solver2.check() == z3.unsat

    def test_refine_inconsistent(self):
        """Refine detects inconsistency."""

        p = ProductDomain(
            interval=Interval.range(1, 10),
            sign=Sign.negative(),
        )

        refined = p.refine()

        assert refined.is_bottom()


class TestAbstractState:
    """Tests for AbstractState."""

    def test_get_set(self):
        """Get and set values."""

        state = AbstractState()

        state.set("x", ProductDomain.from_concrete(5))

        x_value = state.get("x")

        assert x_value.interval.lo == 5

    def test_get_unknown(self):
        """Get unknown variable returns top."""

        state = AbstractState()

        x_value = state.get("unknown")

        assert x_value.interval.is_top()

    def test_join_states(self):
        """Join two states."""

        s1 = AbstractState()

        s1.set("x", ProductDomain.from_concrete(5))

        s2 = AbstractState()

        s2.set("x", ProductDomain.from_concrete(10))

        joined = s1.join(s2)

        x_value = joined.get("x")

        assert x_value.interval.lo == 5

        assert x_value.interval.hi == 10

    def test_widen_states(self):
        """Widen states."""

        s1 = AbstractState()

        s1.set("x", ProductDomain(interval=Interval.range(0, 10)))

        s2 = AbstractState()

        s2.set("x", ProductDomain(interval=Interval.range(-5, 15)))

        widened = s1.widen(s2)

        x_value = widened.get("x")

        assert x_value.interval.is_top()

    def test_to_z3_constraints(self):
        """Convert to Z3 constraints."""

        state = AbstractState()

        state.set("x", ProductDomain(interval=Interval.range(0, 10)))

        state.set("y", ProductDomain(sign=Sign.positive()))

        constraints = state.to_z3_constraints()

        assert len(constraints) == 2


class TestAbstractInterpreter:
    """Tests for AbstractInterpreter."""

    def test_analyze_assignment(self):
        """Analyze assignment."""

        interp = AbstractInterpreter()

        state = AbstractState()

        new_state = interp.analyze_assignment(
            state,
            "x",
            ProductDomain.from_concrete(5),
        )

        assert new_state.get("x").interval.lo == 5

    def test_analyze_add(self):
        """Analyze addition."""

        interp = AbstractInterpreter()

        left = ProductDomain.from_concrete(3)

        right = ProductDomain.from_concrete(5)

        result = interp.analyze_binary_op("+", left, right)

        assert result.interval.lo == 8

        assert result.interval.hi == 8

    def test_analyze_mul(self):
        """Analyze multiplication."""

        interp = AbstractInterpreter()

        left = ProductDomain.from_concrete(4)

        right = ProductDomain.from_concrete(3)

        result = interp.analyze_binary_op("*", left, right)

        assert result.interval.lo == 12

        assert result.parity.value == ParityValue.EVEN

    def test_analyze_comparison_refine(self):
        """Comparison refines interval."""

        interp = AbstractInterpreter()

        left = ProductDomain()

        right = ProductDomain.from_concrete(10)

        left_refined, _ = interp.analyze_comparison("<", left, right)

        assert left_refined.interval.hi == 9

    def test_analyze_loop(self):
        """Analyze loop with widening."""

        interp = AbstractInterpreter()

        init_state = AbstractState()

        init_state.set("x", ProductDomain.from_concrete(0))

        def loop_body(state: AbstractState) -> AbstractState:
            x = state.get("x")

            one = ProductDomain.from_concrete(1)

            new_x = interp.analyze_binary_op("+", x, one)

            result = state.copy()

            result.set("x", new_x)

            return result

        final = interp.analyze_loop(init_state, loop_body)

        x_value = final.get("x")

        assert x_value.interval.hi is None


class TestUseCases:
    """Tests for real-world use cases."""

    def test_array_bounds(self):
        """Array bounds checking with intervals."""

        index = Interval.range(0, 9)

        length = Interval.from_concrete(10)

        assert index.hi < length.lo

    def test_division_by_zero(self):
        """Division by zero with sign domain."""

        divisor = Sign.positive()

        assert divisor.value == SignValue.POS

    def test_loop_termination(self):
        """Loop termination with interval widening."""

        loop_var = Interval.range(0, 10)

        for _ in range(5):
            new_loop_var = loop_var + Interval.from_concrete(1)

            loop_var = loop_var.widen(new_loop_var)

        assert loop_var.lo == 0 or loop_var.lo is None

    def test_parity_invariant(self):
        """Prove parity invariant."""

        x = Parity.even()

        two = Parity.even()

        result = x + two

        assert result.value == ParityValue.EVEN

    def test_null_dereference(self):
        """Null dereference check."""

        x = Null.top()

        x_refined = x.meet(Null.non_null())

        assert x_refined.is_non_null()

        assert not x_refined.may_be_null()
