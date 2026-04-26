"""Tests for pysymex.analysis.abstract.domains — abstract interpretation domains."""

from __future__ import annotations

import z3

from pysymex.analysis.abstract.domains import (
    AbstractInterpreter,
    AbstractState,
    ProductDomain,
)
from pysymex.analysis.abstract.domains.base import Interval
from pysymex.analysis.abstract.domains.lattices import (
    Null,
    NullValue,
    Parity,
    ParityValue,
    Sign,
    SignValue,
)


class TestProductDomain:
    """Tests for ProductDomain component-wise operations."""

    def test_default_is_top(self) -> None:
        """Default ProductDomain is top (no constraints)."""
        pd = ProductDomain()
        assert pd.is_bottom() is False

    def test_from_concrete_int(self) -> None:
        """from_concrete creates a point domain from an int."""
        pd = ProductDomain.from_concrete(42)
        assert pd.interval.lo == 42
        assert pd.interval.hi == 42

    def test_from_concrete_non_int(self) -> None:
        """from_concrete with non-int returns top."""
        pd = ProductDomain.from_concrete("hello")
        assert pd.is_bottom() is False

    def test_is_bottom_when_interval_bottom(self) -> None:
        """is_bottom is True when interval is bottom."""
        pd = ProductDomain(interval=Interval.bottom())
        assert pd.is_bottom() is True

    def test_is_bottom_when_sign_bottom(self) -> None:
        """is_bottom is True when sign is bottom."""
        pd = ProductDomain(sign=Sign.bottom())
        assert pd.is_bottom() is True

    def test_join(self) -> None:
        """Join combines two domains."""
        pd1 = ProductDomain.from_concrete(5)
        pd2 = ProductDomain.from_concrete(10)
        joined = pd1.join(pd2)
        assert joined.interval.lo is not None
        assert joined.interval.lo <= 5
        assert joined.interval.hi is not None
        assert joined.interval.hi >= 10

    def test_meet(self) -> None:
        """Meet intersects two domains."""
        pd1 = ProductDomain(interval=Interval(0, 10))
        pd2 = ProductDomain(interval=Interval(5, 15))
        met = pd1.meet(pd2)
        assert met.interval.lo == 5
        assert met.interval.hi == 10

    def test_widen(self) -> None:
        """Widen produces a wider interval."""
        pd1 = ProductDomain(interval=Interval(0, 5))
        pd2 = ProductDomain(interval=Interval(0, 10))
        widened = pd1.widen(pd2)
        assert widened.interval.hi is None or widened.interval.hi >= 10

    def test_to_z3_constraint(self) -> None:
        """to_z3_constraint produces a Z3 BoolRef."""
        pd = ProductDomain.from_concrete(5)
        var = z3.Int("x")
        constraint = pd.to_z3_constraint(var)
        assert isinstance(constraint, z3.ExprRef)

    def test_refine_consistent(self) -> None:
        """refine() on consistent domain returns itself."""
        pd = ProductDomain.from_concrete(5)
        refined = pd.refine()
        assert refined.interval.lo == 5

    def test_refine_inconsistent_sign_interval(self) -> None:
        """refine() detects inconsistent sign+interval → bottom."""
        pd = ProductDomain(
            interval=Interval(1, 10),
            sign=Sign(SignValue.NEG),
        )
        refined = pd.refine()
        assert refined.is_bottom() is True

    def test_refine_pos_sign_negative_interval(self) -> None:
        """POS sign with hi<=0 → bottom."""
        pd = ProductDomain(
            interval=Interval(-5, 0),
            sign=Sign(SignValue.POS),
        )
        refined = pd.refine()
        assert refined.is_bottom() is True

    def test_refine_zero_sign_not_containing_zero(self) -> None:
        """ZERO sign with interval not containing 0 → bottom."""
        pd = ProductDomain(
            interval=Interval(1, 5),
            sign=Sign(SignValue.ZERO),
        )
        refined = pd.refine()
        assert refined.is_bottom() is True

    def test_refine_parity_mismatch(self) -> None:
        """EVEN parity with odd constant → bottom."""
        pd = ProductDomain(
            interval=Interval(3, 3),
            parity=Parity(ParityValue.EVEN),
        )
        refined = pd.refine()
        assert refined.is_bottom() is True


class TestAbstractState:
    """Tests for AbstractState variable tracking."""

    def test_get_missing_returns_top(self) -> None:
        """get() on missing variable returns top ProductDomain."""
        state = AbstractState()
        pd = state.get("x")
        assert pd.is_bottom() is False

    def test_set_and_get(self) -> None:
        """set() followed by get() returns the value."""
        state = AbstractState()
        pd = ProductDomain.from_concrete(42)
        state.set("x", pd)
        assert state.get("x").interval.lo == 42

    def test_join_states(self) -> None:
        """join() merges two states."""
        s1 = AbstractState()
        s1.set("x", ProductDomain.from_concrete(5))
        s2 = AbstractState()
        s2.set("x", ProductDomain.from_concrete(10))
        joined = s1.join(s2)
        pd = joined.get("x")
        assert pd.interval.lo is not None
        assert pd.interval.lo <= 5

    def test_widen_states(self) -> None:
        """widen() produces widened state."""
        s1 = AbstractState()
        s1.set("x", ProductDomain(interval=Interval(0, 5)))
        s2 = AbstractState()
        s2.set("x", ProductDomain(interval=Interval(0, 10)))
        widened = s1.widen(s2)
        assert widened.get("x").interval.hi is None or widened.get("x").interval.hi >= 10

    def test_to_z3_constraints(self) -> None:
        """to_z3_constraints produces Z3 constraints."""
        state = AbstractState()
        state.set("x", ProductDomain.from_concrete(5))
        constraints = state.to_z3_constraints()
        assert len(constraints) >= 1
        assert all(isinstance(c, z3.ExprRef) for c in constraints)

    def test_copy(self) -> None:
        """copy() produces independent state."""
        state = AbstractState()
        state.set("x", ProductDomain.from_concrete(5))
        copied = state.copy()
        copied.set("x", ProductDomain.from_concrete(10))
        assert state.get("x").interval.lo == 5
        assert copied.get("x").interval.lo == 10


class TestAbstractInterpreter:
    """Tests for AbstractInterpreter analysis methods."""

    def test_init_default_threshold(self) -> None:
        """Default widening threshold is 3."""
        ai = AbstractInterpreter()
        assert ai.widening_threshold == 3

    def test_init_custom_threshold(self) -> None:
        """Custom widening threshold is stored."""
        ai = AbstractInterpreter(widening_threshold=5)
        assert ai.widening_threshold == 5

    def test_analyze_assignment(self) -> None:
        """analyze_assignment updates target variable."""
        ai = AbstractInterpreter()
        state = AbstractState()
        pd = ProductDomain.from_concrete(42)
        new_state = ai.analyze_assignment(state, "x", pd)
        assert new_state.get("x").interval.lo == 42

    def test_analyze_binary_add(self) -> None:
        """analyze_binary_op with '+' produces correct interval."""
        ai = AbstractInterpreter()
        left = ProductDomain.from_concrete(5)
        right = ProductDomain.from_concrete(3)
        result = ai.analyze_binary_op("+", left, right)
        assert result.interval.lo == 8
        assert result.interval.hi == 8

    def test_analyze_binary_sub(self) -> None:
        """analyze_binary_op with '-' produces correct interval."""
        ai = AbstractInterpreter()
        left = ProductDomain.from_concrete(10)
        right = ProductDomain.from_concrete(3)
        result = ai.analyze_binary_op("-", left, right)
        assert result.interval.lo == 7
        assert result.interval.hi == 7

    def test_analyze_binary_mul(self) -> None:
        """analyze_binary_op with '*' produces correct interval."""
        ai = AbstractInterpreter()
        left = ProductDomain.from_concrete(4)
        right = ProductDomain.from_concrete(3)
        result = ai.analyze_binary_op("*", left, right)
        assert result.interval.lo == 12
        assert result.interval.hi == 12

    def test_analyze_binary_unknown_op(self) -> None:
        """analyze_binary_op with unknown op returns top."""
        ai = AbstractInterpreter()
        left = ProductDomain.from_concrete(5)
        right = ProductDomain.from_concrete(3)
        result = ai.analyze_binary_op("//", left, right)
        assert result.is_bottom() is False

    def test_analyze_comparison_less_than(self) -> None:
        """analyze_comparison with '<' refines left bound."""
        ai = AbstractInterpreter()
        left = ProductDomain(interval=Interval(0, 100))
        right = ProductDomain.from_concrete(10)
        refined_left, refined_right = ai.analyze_comparison("<", left, right)
        assert refined_left.interval.hi is not None
        assert refined_left.interval.hi <= 9

    def test_analyze_comparison_greater_than(self) -> None:
        """analyze_comparison with '>' refines left bound."""
        ai = AbstractInterpreter()
        left = ProductDomain(interval=Interval(0, 100))
        right = ProductDomain.from_concrete(10)
        refined_left, _ = ai.analyze_comparison(">", left, right)
        assert refined_left.interval.lo is not None
        assert refined_left.interval.lo >= 11

    def test_analyze_loop_fixpoint(self) -> None:
        """analyze_loop reaches fixpoint."""
        ai = AbstractInterpreter()
        init = AbstractState()
        init.set("x", ProductDomain.from_concrete(0))

        def body(state: AbstractState) -> AbstractState:
            """Increment x by 1."""
            result = state.copy()
            old_x = state.get("x")
            one = ProductDomain.from_concrete(1)
            new_x = ai.analyze_binary_op("+", old_x, one)
            result.set("x", new_x)
            return result

        final = ai.analyze_loop(init, body, max_iterations=20)
        assert final.get("x").interval.lo is not None

    def test_add_signs_pos_pos(self) -> None:
        """Adding POS + POS gives POS."""
        ai = AbstractInterpreter()
        result = ai._add_signs(Sign(SignValue.POS), Sign(SignValue.POS))
        assert result.value == SignValue.POS

    def test_add_signs_neg_neg(self) -> None:
        """Adding NEG + NEG gives NEG."""
        ai = AbstractInterpreter()
        result = ai._add_signs(Sign(SignValue.NEG), Sign(SignValue.NEG))
        assert result.value == SignValue.NEG

    def test_add_signs_zero_x(self) -> None:
        """Adding ZERO + X gives X."""
        ai = AbstractInterpreter()
        result = ai._add_signs(Sign(SignValue.ZERO), Sign(SignValue.POS))
        assert result.value == SignValue.POS

    def test_sub_signs_pos_neg(self) -> None:
        """Subtracting POS - NEG gives POS."""
        ai = AbstractInterpreter()
        result = ai._sub_signs(Sign(SignValue.POS), Sign(SignValue.NEG))
        assert result.value == SignValue.POS

    def test_mul_signs_pos_neg(self) -> None:
        """Multiplying POS * NEG gives NEG."""
        ai = AbstractInterpreter()
        result = ai._mul_signs(Sign(SignValue.POS), Sign(SignValue.NEG))
        assert result.value == SignValue.NEG

    def test_mul_signs_neg_neg(self) -> None:
        """Multiplying NEG * NEG gives POS."""
        ai = AbstractInterpreter()
        result = ai._mul_signs(Sign(SignValue.NEG), Sign(SignValue.NEG))
        assert result.value == SignValue.POS

    def test_mul_signs_zero(self) -> None:
        """Multiplying by ZERO gives ZERO."""
        ai = AbstractInterpreter()
        result = ai._mul_signs(Sign(SignValue.POS), Sign(SignValue.ZERO))
        assert result.value == SignValue.ZERO
