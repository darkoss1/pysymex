"""Tests for pysymex.analysis.range_analysis -- Value Range Analysis.

Covers:
- Range creation (exact, full, empty, at_least, at_most, between)
- Range predicates (contains, may_be_zero, must_be_positive, ...)
- Range arithmetic (add, sub, neg, mul, div, mod)
- Range lattice operations (union, intersect, widen, narrow, subset_of)
- RangeState stack/variable operations and join/widen
- RangeWarning creation
- RangeAnalyzer.analyze on simple functions
- ValueRangeChecker.check_function and check_array_bounds
"""

from __future__ import annotations

import pytest

from pysymex.analysis.range_analysis import (
    Range,
    RangeAnalyzer,
    RangeState,
    RangeWarning,
    ValueRangeChecker,
)


# ===================================================================
# Range creation
# ===================================================================


class TestRangeCreation:
    """Tests for Range factory methods."""

    def test_exact(self):
        r = Range.exact(5)
        assert r.low == 5
        assert r.high == 5
        assert r.is_exact
        assert r.exact_value == 5

    def test_full(self):
        r = Range.full()
        assert r.low is None
        assert r.high is None
        assert r.is_full()
        assert not r.is_empty

    def test_empty(self):
        r = Range.empty()
        assert r.is_empty
        assert not r.is_full()

    def test_at_least(self):
        r = Range.at_least(3)
        assert r.low == 3
        assert r.high is None

    def test_at_most(self):
        r = Range.at_most(10)
        assert r.low is None
        assert r.high == 10

    def test_between(self):
        r = Range.between(1, 10)
        assert r.low == 1
        assert r.high == 10

    def test_between_invalid_returns_empty(self):
        r = Range.between(10, 1)
        assert r.is_empty


# ===================================================================
# Range predicates
# ===================================================================


class TestRangePredicates:
    """Tests for Range query methods."""

    def test_is_exact_true(self):
        assert Range.exact(7).is_exact is True

    def test_is_exact_false_range(self):
        assert Range.between(1, 5).is_exact is False

    def test_is_exact_false_full(self):
        assert Range.full().is_exact is False

    def test_exact_value_none_for_range(self):
        assert Range.between(1, 5).exact_value is None

    def test_contains_in_range(self):
        r = Range.between(1, 10)
        assert r.contains(5)
        assert r.contains(1)
        assert r.contains(10)

    def test_contains_outside_range(self):
        r = Range.between(1, 10)
        assert not r.contains(0)
        assert not r.contains(11)

    def test_contains_empty_always_false(self):
        r = Range.empty()
        assert not r.contains(0)

    def test_contains_full_always_true(self):
        r = Range.full()
        assert r.contains(0)
        assert r.contains(-1000000)

    def test_may_be_zero_yes(self):
        assert Range.between(-5, 5).may_be_zero()

    def test_may_be_zero_no(self):
        assert not Range.between(1, 10).may_be_zero()

    def test_must_be_positive(self):
        assert Range.between(1, 100).must_be_positive()
        assert not Range.between(-1, 100).must_be_positive()

    def test_must_be_negative(self):
        assert Range.between(-100, -1).must_be_negative()
        assert not Range.between(-100, 1).must_be_negative()

    def test_must_be_non_negative(self):
        assert Range.between(0, 10).must_be_non_negative()
        assert not Range.between(-1, 10).must_be_non_negative()

    def test_must_be_non_positive(self):
        assert Range.between(-10, 0).must_be_non_positive()
        assert not Range.between(-10, 1).must_be_non_positive()

    def test_must_be_non_zero_yes(self):
        assert Range.between(1, 10).must_be_non_zero()

    def test_must_be_non_zero_no(self):
        assert not Range.between(-1, 1).must_be_non_zero()

    def test_must_be_non_zero_empty(self):
        assert Range.empty().must_be_non_zero()


# ===================================================================
# Range arithmetic
# ===================================================================


class TestRangeArithmetic:
    """Tests for Range arithmetic operations."""

    def test_add_exact(self):
        r = Range.exact(3).add(Range.exact(4))
        assert r.low == 7 and r.high == 7

    def test_add_ranges(self):
        r = Range.between(1, 5).add(Range.between(10, 20))
        assert r.low == 11
        assert r.high == 25

    def test_add_empty(self):
        r = Range.empty().add(Range.exact(5))
        assert r.is_empty

    def test_sub_exact(self):
        r = Range.exact(10).sub(Range.exact(3))
        assert r.low == 7 and r.high == 7

    def test_sub_ranges(self):
        r = Range.between(5, 10).sub(Range.between(1, 3))
        assert r.low == 2
        assert r.high == 9

    def test_sub_empty(self):
        r = Range.exact(5).sub(Range.empty())
        assert r.is_empty

    def test_neg_exact(self):
        r = Range.exact(5).neg()
        assert r.low == -5 and r.high == -5

    def test_neg_range(self):
        r = Range.between(-3, 7).neg()
        assert r.low == -7
        assert r.high == 3

    def test_neg_empty(self):
        assert Range.empty().neg().is_empty

    def test_mul_exact(self):
        r = Range.exact(3).mul(Range.exact(4))
        assert r.low == 12 and r.high == 12

    def test_mul_ranges(self):
        r = Range.between(2, 3).mul(Range.between(4, 5))
        assert r.low == 8
        assert r.high == 15

    def test_mul_negative(self):
        r = Range.between(-2, 3).mul(Range.between(-1, 4))
        assert r.low == min(-2 * -1, -2 * 4, 3 * -1, 3 * 4)
        assert r.high == max(-2 * -1, -2 * 4, 3 * -1, 3 * 4)

    def test_mul_full_returns_full(self):
        r = Range.full().mul(Range.exact(2))
        assert r.is_full()

    def test_div_exact(self):
        r, may_zero = Range.exact(10).div(Range.exact(2))
        assert r.low == 5 and r.high == 5
        assert not may_zero

    def test_div_by_zero_exact(self):
        r, may_zero = Range.exact(10).div(Range.exact(0))
        assert r.is_empty
        assert may_zero

    def test_div_may_contain_zero(self):
        r, may_zero = Range.exact(10).div(Range.between(-1, 1))
        assert may_zero

    def test_mod_exact(self):
        r, may_zero = Range.exact(10).mod(Range.exact(3))
        assert r.low == 0 and r.high == 2
        assert not may_zero

    def test_mod_by_zero(self):
        r, may_zero = Range.exact(10).mod(Range.exact(0))
        assert r.is_empty
        assert may_zero


# ===================================================================
# Range lattice operations
# ===================================================================


class TestRangeLattice:
    """Tests for Range lattice operations."""

    def test_union_basic(self):
        r = Range.between(1, 5).union(Range.between(3, 10))
        assert r.low == 1
        assert r.high == 10

    def test_union_disjoint(self):
        r = Range.between(1, 3).union(Range.between(7, 10))
        assert r.low == 1
        assert r.high == 10

    def test_union_with_empty(self):
        r = Range.between(1, 5).union(Range.empty())
        assert r.low == 1 and r.high == 5

    def test_union_empty_left(self):
        r = Range.empty().union(Range.between(1, 5))
        assert r.low == 1 and r.high == 5

    def test_intersect_overlap(self):
        r = Range.between(1, 10).intersect(Range.between(5, 15))
        assert r.low == 5
        assert r.high == 10

    def test_intersect_disjoint(self):
        r = Range.between(1, 3).intersect(Range.between(5, 10))
        assert r.is_empty

    def test_intersect_with_empty(self):
        r = Range.between(1, 10).intersect(Range.empty())
        assert r.is_empty

    def test_widen_growing_high(self):
        r1 = Range.between(0, 5)
        r2 = Range.between(0, 10)
        w = r1.widen(r2)
        # High grows, so widened to infinity
        assert w.high is None
        assert w.low == 0

    def test_widen_stable(self):
        r1 = Range.between(0, 10)
        r2 = Range.between(0, 5)
        w = r1.widen(r2)
        assert w.low == 0
        assert w.high == 10

    def test_widen_with_empty(self):
        r = Range.empty().widen(Range.between(1, 5))
        assert r.low == 1 and r.high == 5

    def test_narrow(self):
        r1 = Range(None, None)  # full
        r2 = Range.between(0, 10)
        n = r1.narrow(r2)
        assert n.low == 0
        assert n.high == 10

    def test_subset_of_exact_in_range(self):
        assert Range.exact(5).subset_of(Range.between(1, 10))

    def test_subset_of_not(self):
        assert not Range.between(1, 10).subset_of(Range.exact(5))

    def test_subset_of_empty(self):
        assert Range.empty().subset_of(Range.between(1, 10))

    def test_subset_of_self(self):
        r = Range.between(1, 10)
        assert r.subset_of(r)


# ===================================================================
# Range __str__
# ===================================================================


class TestRangeStr:
    """Tests for Range string representation."""

    def test_str_exact(self):
        s = str(Range.exact(5))
        assert "5" in s

    def test_str_empty(self):
        assert str(Range.empty()) == "\u2205"

    def test_str_full(self):
        s = str(Range.full())
        assert "-" in s and "+" in s


# ===================================================================
# RangeState tests
# ===================================================================


class TestRangeState:
    """Tests for RangeState."""

    def test_bottom(self):
        s = RangeState.bottom()
        assert s.is_bottom

    def test_top(self):
        s = RangeState.top()
        assert not s.is_bottom

    def test_set_and_get(self):
        s = RangeState()
        s.set("x", Range.exact(5))
        assert s.get("x").is_exact
        assert s.get("x").exact_value == 5

    def test_get_unknown_returns_full(self):
        s = RangeState()
        assert s.get("unknown_var").is_full()

    def test_push_and_pop(self):
        s = RangeState()
        s.push(Range.exact(3))
        r = s.pop()
        assert r.exact_value == 3

    def test_pop_empty_returns_full(self):
        s = RangeState()
        r = s.pop()
        assert r.is_full()

    def test_peek(self):
        s = RangeState()
        s.push(Range.exact(1))
        s.push(Range.exact(2))
        assert s.peek(0).exact_value == 2
        assert s.peek(1).exact_value == 1

    def test_copy(self):
        s = RangeState()
        s.set("x", Range.exact(5))
        s.push(Range.exact(1))
        c = s.copy()
        assert c.get("x").exact_value == 5
        assert c.pop().exact_value == 1
        # Original unchanged
        assert s.pop().exact_value == 1

    def test_copy_bottom(self):
        s = RangeState.bottom()
        c = s.copy()
        assert c.is_bottom

    def test_join(self):
        s1 = RangeState()
        s1.set("x", Range.between(1, 5))
        s2 = RangeState()
        s2.set("x", Range.between(3, 10))
        joined = s1.join(s2)
        assert joined.get("x").low == 1
        assert joined.get("x").high == 10

    def test_join_with_bottom(self):
        s1 = RangeState.bottom()
        s2 = RangeState()
        s2.set("x", Range.exact(5))
        joined = s1.join(s2)
        assert joined.get("x").exact_value == 5

    def test_widen_state(self):
        s1 = RangeState()
        s1.set("x", Range.between(0, 5))
        s2 = RangeState()
        s2.set("x", Range.between(0, 10))
        widened = s1.widen(s2)
        assert widened.get("x").high is None

    def test_subset_of(self):
        s1 = RangeState()
        s1.set("x", Range.exact(5))
        s2 = RangeState()
        s2.set("x", Range.between(1, 10))
        assert s1.subset_of(s2)

    def test_bottom_subset_of_anything(self):
        s1 = RangeState.bottom()
        s2 = RangeState()
        assert s1.subset_of(s2)


# ===================================================================
# RangeWarning tests
# ===================================================================


class TestRangeWarning:
    """Tests for RangeWarning dataclass."""

    def test_creation(self):
        w = RangeWarning(line=10, pc=20, kind="DIVISION_BY_ZERO", message="test")
        assert w.line == 10
        assert w.pc == 20
        assert w.kind == "DIVISION_BY_ZERO"
        assert w.message == "test"
        assert w.range_info is None

    def test_with_range_info(self):
        r = Range.between(-5, 5)
        w = RangeWarning(line=10, pc=20, kind="DIVISION_BY_ZERO", message="test", range_info=r)
        assert w.range_info is r


# ===================================================================
# RangeAnalyzer tests
# ===================================================================


def _simple_add(x):
    y = x + 1
    return y


def _const_arith():
    a = 3
    b = 4
    return a + b


def _division_possible(x, y):
    return x / y


def _guarded_division(x, y):
    if y != 0:
        return x / y
    return 0


class TestRangeAnalyzer:
    """Tests for RangeAnalyzer.analyze."""

    def test_analyze_returns_tuple(self):
        analyzer = RangeAnalyzer()
        ranges, warnings = analyzer.analyze(_simple_add.__code__)
        assert isinstance(ranges, dict)
        assert isinstance(warnings, list)

    def test_analyze_const_arith(self):
        analyzer = RangeAnalyzer()
        ranges, warnings = analyzer.analyze(_const_arith.__code__)
        assert isinstance(ranges, dict)

    def test_analyze_division(self):
        analyzer = RangeAnalyzer()
        ranges, warnings = analyzer.analyze(_division_possible.__code__)
        assert isinstance(ranges, dict)
        assert isinstance(warnings, list)

    def test_warnings_are_range_warnings(self):
        analyzer = RangeAnalyzer()
        _, warnings = analyzer.analyze(_division_possible.__code__)
        for w in warnings:
            assert isinstance(w, RangeWarning)


# ===================================================================
# ValueRangeChecker tests
# ===================================================================


class TestValueRangeChecker:
    """Tests for ValueRangeChecker."""

    def test_check_function(self):
        checker = ValueRangeChecker()
        warnings = checker.check_function(_simple_add.__code__)
        assert isinstance(warnings, list)

    def test_check_array_bounds_in_range(self):
        checker = ValueRangeChecker()
        result = checker.check_array_bounds(Range.between(0, 4), array_size=5)
        assert result is None

    def test_check_array_bounds_out_of_bounds_high(self):
        checker = ValueRangeChecker()
        result = checker.check_array_bounds(Range.between(0, 10), array_size=5)
        assert result is not None
        assert "out of bounds" in result

    def test_check_array_bounds_out_of_bounds_negative(self):
        checker = ValueRangeChecker()
        result = checker.check_array_bounds(Range.between(-10, 0), array_size=5)
        assert result is not None
        assert "too negative" in result

    def test_check_array_bounds_empty_range(self):
        checker = ValueRangeChecker()
        result = checker.check_array_bounds(Range.empty(), array_size=5)
        assert result is None

    def test_check_array_bounds_exact_valid(self):
        checker = ValueRangeChecker()
        result = checker.check_array_bounds(Range.exact(2), array_size=5)
        assert result is None

    def test_check_array_bounds_exact_invalid(self):
        checker = ValueRangeChecker()
        result = checker.check_array_bounds(Range.exact(5), array_size=5)
        assert result is not None
