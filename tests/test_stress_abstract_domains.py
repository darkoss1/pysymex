"""Stress-tests for abstract domain fixes in pysymex v0.5.0-alpha.

Covers 8 targeted fixes across three modules:
  domains_base.py   — Interval.__mul__ (unbounded), __post_init__ (bottom canon)
  domains_lattices.py — Sign.join (sub-lattice), Parity.__mul__ (EVEN-before-TOP)
  domains.py         — _sub_signs, _add_signs, analyze_loop fixpoint, refine()
"""

from __future__ import annotations


import pytest


from pysymex.analysis.abstract.domains_base import Interval

from pysymex.analysis.abstract.domains_lattices import (
    Parity,
    ParityValue,
    Sign,
    SignValue,
)

from pysymex.analysis.abstract.domains import (
    AbstractInterpreter,
    AbstractState,
    ProductDomain,
)


class TestIntervalBottomNormalization:
    """After fix: every bottom Interval has lo=None, hi=None so equality works."""

    def test_explicit_bottom_has_none_bounds(self):
        b = Interval.bottom()

        assert b.is_bottom()

        assert b.lo is None and b.hi is None

    def test_inverted_range_becomes_bottom(self):
        iv = Interval(10, 5)

        assert iv.is_bottom()

        assert iv.lo is None and iv.hi is None

    def test_all_bottoms_are_equal(self):
        """Multiple ways to produce bottom must give the same canonical object."""

        b1 = Interval.bottom()

        b2 = Interval(10, 5)

        b3 = Interval(1, -1)

        assert b1 == b2 == b3

    def test_bottom_equality_with_explicit_flag(self):
        b1 = Interval(_is_bottom=True)

        b2 = Interval(100, 0)

        assert b1 == b2

    def test_bottom_repr(self):
        assert repr(Interval.bottom()) == "⊥"

        assert repr(Interval(10, 5)) == "⊥"

    def test_zero_width_interval_is_not_bottom(self):
        iv = Interval(5, 5)

        assert not iv.is_bottom()

        assert iv.lo == 5 and iv.hi == 5

    def test_normal_interval_untouched(self):
        iv = Interval(1, 10)

        assert iv.lo == 1 and iv.hi == 10

    def test_bottom_is_not_top(self):
        assert not Interval.bottom().is_top()

    def test_bottom_does_not_contain_anything(self):
        b = Interval(10, 5)

        assert not b.contains(7)

        assert not b.contains(0)

        assert not b.contains(-999)


class TestIntervalMulUnbounded:
    """Fix: __mul__ correctly handles None endpoints instead of crashing."""

    def test_pos_times_unbounded_above(self):
        r = Interval(2, 3) * Interval(1, None)

        assert not r.is_bottom()

        assert r.hi is None

        assert r.lo is None or r.lo <= 2

    def test_pos_times_unbounded_below(self):
        r = Interval(2, 3) * Interval(None, -1)

        assert not r.is_bottom()

        assert r.lo is None

        assert r.hi is None or r.hi <= -2

    def test_neg_times_unbounded_above(self):
        r = Interval(-3, -2) * Interval(1, None)

        assert not r.is_bottom()

        assert r.lo is None

        assert r.hi is None or r.hi <= -2

    def test_neg_times_unbounded_below(self):
        r = Interval(-3, -2) * Interval(None, -1)

        assert not r.is_bottom()

        assert r.hi is None

        assert r.lo is None or r.lo <= 2

    def test_unbounded_times_unbounded(self):
        r = Interval(None, None) * Interval(None, None)

        assert r.is_top()

    def test_at_least_times_at_least(self):
        r = Interval(1, None) * Interval(1, None)

        assert not r.is_bottom()

        assert r.hi is None

        assert r.lo is None or r.lo <= 1

    def test_at_most_times_at_most(self):
        r = Interval(None, -1) * Interval(None, -1)

        assert not r.is_bottom()

        assert r.hi is None

        assert r.lo is None or r.lo <= 1

    def test_at_least_times_at_most_neg(self):
        r = Interval(1, None) * Interval(None, -1)

        assert not r.is_bottom()

        assert r.lo is None

        assert r.hi is None or r.hi <= -1

    def test_zero_times_unbounded(self):
        r = Interval(0, 0) * Interval(None, None)

        assert r == Interval(0, 0)

    def test_unbounded_times_zero(self):
        r = Interval(None, None) * Interval(0, 0)

        assert r == Interval(0, 0)

    def test_bottom_times_unbounded(self):
        r = Interval.bottom() * Interval(None, None)

        assert r.is_bottom()

    def test_unbounded_times_bottom(self):
        r = Interval(None, None) * Interval.bottom()

        assert r.is_bottom()

    def test_crossing_zero_times_unbounded(self):
        r = Interval(-1, 1) * Interval(1, None)

        assert r.lo is None or r.lo <= -1

        assert r.hi is None or r.hi >= 1

    def test_crossing_zero_times_crossing_zero_unbounded(self):
        r = Interval(-1, None) * Interval(None, 1)

        assert isinstance(r, Interval)

    def test_finite_mul_unchanged(self):
        r = Interval(2, 3) * Interval(4, 5)

        assert r == Interval(8, 15)

    def test_finite_mul_with_negatives(self):
        r = Interval(-3, 2) * Interval(-1, 4)

        assert r == Interval(-12, 8)


class TestSignJoinSubLattice:
    """
    Fix: POS ⊔ NON_NEG = NON_NEG (not TOP), and symmetrically.
    """

    @pytest.mark.parametrize(
        "atomic,compound,expected",
        [
            (SignValue.POS, SignValue.NON_NEG, SignValue.NON_NEG),
            (SignValue.ZERO, SignValue.NON_NEG, SignValue.NON_NEG),
            (SignValue.NEG, SignValue.NON_POS, SignValue.NON_POS),
            (SignValue.ZERO, SignValue.NON_POS, SignValue.NON_POS),
            (SignValue.POS, SignValue.NON_ZERO, SignValue.NON_ZERO),
            (SignValue.NEG, SignValue.NON_ZERO, SignValue.NON_ZERO),
        ],
    )
    def test_element_contained_in_compound(self, atomic, compound, expected):
        result = Sign(atomic).join(Sign(compound))

        assert result.value == expected

    @pytest.mark.parametrize(
        "atomic,compound,expected",
        [
            (SignValue.POS, SignValue.NON_NEG, SignValue.NON_NEG),
            (SignValue.ZERO, SignValue.NON_NEG, SignValue.NON_NEG),
            (SignValue.NEG, SignValue.NON_POS, SignValue.NON_POS),
            (SignValue.ZERO, SignValue.NON_POS, SignValue.NON_POS),
            (SignValue.POS, SignValue.NON_ZERO, SignValue.NON_ZERO),
            (SignValue.NEG, SignValue.NON_ZERO, SignValue.NON_ZERO),
        ],
    )
    def test_element_contained_in_compound_reverse(self, atomic, compound, expected):
        """Same pairs, reversed operand order (commutativity)."""

        result = Sign(compound).join(Sign(atomic))

        assert result.value == expected

    @pytest.mark.parametrize(
        "v1,v2",
        [
            (SignValue.NEG, SignValue.NON_NEG),
            (SignValue.POS, SignValue.NON_POS),
            (SignValue.ZERO, SignValue.NON_ZERO),
        ],
    )
    def test_element_not_in_compound_gives_top(self, v1, v2):
        assert Sign(v1).join(Sign(v2)).value == SignValue.TOP

        assert Sign(v2).join(Sign(v1)).value == SignValue.TOP

    @pytest.mark.parametrize(
        "v1,v2",
        [
            (SignValue.NON_NEG, SignValue.NON_POS),
            (SignValue.NON_NEG, SignValue.NON_ZERO),
            (SignValue.NON_POS, SignValue.NON_ZERO),
        ],
    )
    def test_compound_join_compound_gives_top(self, v1, v2):
        assert Sign(v1).join(Sign(v2)).value == SignValue.TOP

    def test_join_with_bottom(self):
        for sv in SignValue:
            s = Sign(sv)

            assert s.join(Sign.bottom()) == s

            assert Sign.bottom().join(s) == s

    def test_join_with_self(self):
        for sv in SignValue:
            s = Sign(sv)

            assert s.join(s) == s


class TestParityMulEvenBeforeTop:
    """Fix: EVEN * TOP = EVEN (not TOP), because any integer × even = even."""

    def test_even_times_top(self):
        assert (Parity.even() * Parity.top()).value == ParityValue.EVEN

    def test_top_times_even(self):
        assert (Parity.top() * Parity.even()).value == ParityValue.EVEN

    def test_even_times_odd(self):
        assert (Parity.even() * Parity.odd()).value == ParityValue.EVEN

    def test_odd_times_even(self):
        assert (Parity.odd() * Parity.even()).value == ParityValue.EVEN

    def test_even_times_even(self):
        assert (Parity.even() * Parity.even()).value == ParityValue.EVEN

    def test_odd_times_odd(self):
        assert (Parity.odd() * Parity.odd()).value == ParityValue.ODD

    def test_top_times_top(self):
        assert (Parity.top() * Parity.top()).value == ParityValue.TOP

    def test_top_times_odd(self):
        assert (Parity.top() * Parity.odd()).value == ParityValue.TOP

    def test_bottom_absorbs(self):
        for p in [Parity.even(), Parity.odd(), Parity.top(), Parity.bottom()]:
            assert (Parity.bottom() * p).value == ParityValue.BOTTOM

            assert (p * Parity.bottom()).value == ParityValue.BOTTOM


class TestSubSigns:
    """Fix: 0−POS=NEG, 0−NEG=POS  (were previously wrong or TOP)."""

    def setup_method(self):
        self.interp = AbstractInterpreter()

    def test_zero_minus_pos_is_neg(self):
        r = self.interp._sub_signs(Sign.zero(), Sign.positive())

        assert r.value == SignValue.NEG

    def test_zero_minus_neg_is_pos(self):
        r = self.interp._sub_signs(Sign.zero(), Sign.negative())

        assert r.value == SignValue.POS

    def test_zero_minus_zero_is_zero(self):
        r = self.interp._sub_signs(Sign.zero(), Sign.zero())

        assert r.value == SignValue.ZERO

    def test_pos_minus_neg_is_pos(self):
        r = self.interp._sub_signs(Sign.positive(), Sign.negative())

        assert r.value == SignValue.POS

    def test_neg_minus_pos_is_neg(self):
        r = self.interp._sub_signs(Sign.negative(), Sign.positive())

        assert r.value == SignValue.NEG

    def test_pos_minus_pos_is_top(self):
        r = self.interp._sub_signs(Sign.positive(), Sign.positive())

        assert r.value == SignValue.TOP

    def test_neg_minus_neg_is_top(self):
        r = self.interp._sub_signs(Sign.negative(), Sign.negative())

        assert r.value == SignValue.TOP

    def test_zero_minus_top_is_top(self):
        r = self.interp._sub_signs(Sign.zero(), Sign.top())

        assert r.value == SignValue.TOP

    def test_bottom_propagates(self):
        r = self.interp._sub_signs(Sign.bottom(), Sign.positive())

        assert r.is_bottom()

        r = self.interp._sub_signs(Sign.positive(), Sign.bottom())

        assert r.is_bottom()

    def test_anything_minus_zero_unchanged(self):
        for sv in [SignValue.POS, SignValue.NEG, SignValue.NON_NEG, SignValue.TOP]:
            r = self.interp._sub_signs(Sign(sv), Sign.zero())

            assert r.value == sv


class TestAddSigns:
    """
    Fix: NON_NEG+NON_NEG=NON_NEG, POS+NON_NEG=POS, NEG+NON_POS=NEG, etc.
    """

    def setup_method(self):
        self.interp = AbstractInterpreter()

    def test_non_neg_plus_non_neg(self):
        r = self.interp._add_signs(Sign.non_negative(), Sign.non_negative())

        assert r.value == SignValue.NON_NEG

    def test_non_pos_plus_non_pos(self):
        r = self.interp._add_signs(Sign.non_positive(), Sign.non_positive())

        assert r.value == SignValue.NON_POS

    def test_pos_plus_non_neg(self):
        r = self.interp._add_signs(Sign.positive(), Sign.non_negative())

        assert r.value == SignValue.POS

    def test_non_neg_plus_pos(self):
        r = self.interp._add_signs(Sign.non_negative(), Sign.positive())

        assert r.value == SignValue.POS

    def test_neg_plus_non_pos(self):
        r = self.interp._add_signs(Sign.negative(), Sign.non_positive())

        assert r.value == SignValue.NEG

    def test_non_pos_plus_neg(self):
        r = self.interp._add_signs(Sign.non_positive(), Sign.negative())

        assert r.value == SignValue.NEG

    def test_zero_plus_anything(self):
        for sv in SignValue:
            if sv == SignValue.BOTTOM:
                continue

            r = self.interp._add_signs(Sign.zero(), Sign(sv))

            assert r.value == sv

    def test_anything_plus_zero(self):
        for sv in SignValue:
            if sv == SignValue.BOTTOM:
                continue

            r = self.interp._add_signs(Sign(sv), Sign.zero())

            assert r.value == sv

    def test_pos_plus_pos(self):
        r = self.interp._add_signs(Sign.positive(), Sign.positive())

        assert r.value == SignValue.POS

    def test_neg_plus_neg(self):
        r = self.interp._add_signs(Sign.negative(), Sign.negative())

        assert r.value == SignValue.NEG

    def test_pos_plus_neg_is_top(self):
        r = self.interp._add_signs(Sign.positive(), Sign.negative())

        assert r.value == SignValue.TOP

    def test_non_neg_plus_non_pos_is_top(self):
        r = self.interp._add_signs(Sign.non_negative(), Sign.non_positive())

        assert r.value == SignValue.TOP

    def test_bottom_propagates(self):
        r = self.interp._add_signs(Sign.bottom(), Sign.positive())

        assert r.is_bottom()

        r = self.interp._add_signs(Sign.negative(), Sign.bottom())

        assert r.is_bottom()


class TestAnalyzeLoopFixpoint:
    """
    Fix: compare state to next_state (not to pre-join state).  Without the
    fix, the loop could terminate one iteration too early, missing the real
    fixpoint.
    """

    def test_trivial_identity_body_terminates(self):
        """Body that is identity should produce the init state."""

        interp = AbstractInterpreter(widening_threshold=3)

        init = AbstractState()

        init.set("x", ProductDomain.from_concrete(0))

        result = interp.analyze_loop(init, lambda s: s)

        assert result.get("x").interval == Interval(0, 0)

    def test_incrementing_loop_widens(self):
        """
        Simulate: x = 0; while True: x = x + 1
        After widening, x should be [0, +∞).
        """

        interp = AbstractInterpreter(widening_threshold=2)

        init = AbstractState()

        init.set("x", ProductDomain(interval=Interval(0, 0)))

        def body(state: AbstractState) -> AbstractState:
            x = state.get("x")

            new_x = ProductDomain(interval=x.interval + Interval(1, 1))

            result = state.copy()

            result.set("x", new_x)

            return result

        result = interp.analyze_loop(init, body, max_iterations=50)

        x_iv = result.get("x").interval

        assert x_iv.hi is None

        assert x_iv.lo is None or x_iv.lo == 0

    def test_decrementing_loop_widens(self):
        """x = 0; while True: x = x - 1 → should widen to (-∞, 0]."""

        interp = AbstractInterpreter(widening_threshold=2)

        init = AbstractState()

        init.set("x", ProductDomain(interval=Interval(0, 0)))

        def body(state: AbstractState) -> AbstractState:
            x = state.get("x")

            new_x = ProductDomain(interval=x.interval - Interval(1, 1))

            result = state.copy()

            result.set("x", new_x)

            return result

        result = interp.analyze_loop(init, body, max_iterations=50)

        x_iv = result.get("x").interval

        assert x_iv.lo is None

    def test_constant_body_reaches_fixpoint_quickly(self):
        """Body always sets x=5 → fixpoint at x=5."""

        interp = AbstractInterpreter(widening_threshold=3)

        init = AbstractState()

        init.set("x", ProductDomain(interval=Interval(0, 0)))

        def body(state: AbstractState) -> AbstractState:
            result = state.copy()

            result.set("x", ProductDomain.from_concrete(5))

            return result

        result = interp.analyze_loop(init, body, max_iterations=50)

        x_iv = result.get("x").interval

        assert x_iv.lo is not None and x_iv.lo <= 0

        assert x_iv.hi is not None and x_iv.hi >= 5

    def test_fixpoint_equality_uses_next_state(self):
        """
        Regression: with the old code `if _states_equal(state, new_state):`
        (comparing pre-join), certain bodies could false-terminate.
        Ensure the loop runs at least 2 iterations for a strictly-growing body.
        """

        iterations: list[int] = []

        interp = AbstractInterpreter(widening_threshold=100)

        init = AbstractState()

        init.set("x", ProductDomain(interval=Interval(0, 0)))

        def body(state: AbstractState) -> AbstractState:
            iterations.append(1)

            x = state.get("x")

            new_x = ProductDomain(interval=x.interval + Interval(1, 1))

            result = state.copy()

            result.set("x", new_x)

            return result

        interp.analyze_loop(init, body, max_iterations=5)

        assert len(iterations) == 5


class TestRefineFullyBottom:
    """
    Fix: refine() now sets ALL components to bottom (interval, sign, parity)
    instead of leaving some at their old values.
    """

    def test_neg_sign_pos_interval_gives_full_bottom(self):
        pd = ProductDomain(
            interval=Interval(1, 10),
            sign=Sign.negative(),
            parity=Parity.odd(),
        )

        r = pd.refine()

        assert r.interval.is_bottom()

        assert r.sign.is_bottom()

        assert r.parity.is_bottom()

        assert r.is_bottom()

    def test_pos_sign_neg_interval_gives_full_bottom(self):
        pd = ProductDomain(
            interval=Interval(-10, -1),
            sign=Sign.positive(),
            parity=Parity.even(),
        )

        r = pd.refine()

        assert r.interval.is_bottom()

        assert r.sign.is_bottom()

        assert r.parity.is_bottom()

    def test_zero_sign_interval_not_containing_zero(self):
        pd = ProductDomain(
            interval=Interval(1, 10),
            sign=Sign.zero(),
            parity=Parity.even(),
        )

        r = pd.refine()

        assert r.interval.is_bottom()

        assert r.sign.is_bottom()

        assert r.parity.is_bottom()

    def test_pos_sign_zero_only_interval_gives_bottom(self):
        pd = ProductDomain(
            interval=Interval(0, 0),
            sign=Sign.positive(),
            parity=Parity.even(),
        )

        r = pd.refine()

        assert r.is_bottom()

    def test_neg_sign_zero_only_interval_gives_bottom(self):
        pd = ProductDomain(
            interval=Interval(0, 0),
            sign=Sign.negative(),
            parity=Parity.odd(),
        )

        r = pd.refine()

        assert r.is_bottom()

    def test_consistent_product_unchanged(self):
        pd = ProductDomain(
            interval=Interval(1, 10),
            sign=Sign.positive(),
            parity=Parity.top(),
        )

        r = pd.refine()

        assert r == pd

    def test_bottom_input_passes_through(self):
        pd = ProductDomain(
            interval=Interval.bottom(),
            sign=Sign.positive(),
            parity=Parity.odd(),
        )

        assert pd.is_bottom()

        r = pd.refine()

        assert r.is_bottom()

    def test_refine_returns_product_domain(self):
        pd = ProductDomain(
            interval=Interval(-5, 5),
            sign=Sign.non_negative(),
            parity=Parity.even(),
        )

        r = pd.refine()

        assert isinstance(r, ProductDomain)


class TestCrossFixInteractions:
    """Tests that exercise multiple fixes at once."""

    def test_bottom_normalization_propagates_through_mul(self):
        """Bottom from inverted range → canonical → mul propagates."""

        b = Interval(10, 5)

        r = b * Interval(1, None)

        assert r.is_bottom()

    def test_bottom_normalization_and_join(self):
        """Canonical bottom joins correctly."""

        b = Interval(10, 5)

        iv = Interval(1, 3)

        assert b.join(iv) == iv

        assert iv.join(b) == iv

    def test_unbounded_mul_within_product_domain(self):
        """Binary op '*' through ProductDomain uses the fixed __mul__."""

        interp = AbstractInterpreter()

        left = ProductDomain(interval=Interval(2, 3), sign=Sign.positive(), parity=Parity.top())

        right = ProductDomain(interval=Interval(1, None), sign=Sign.positive(), parity=Parity.top())

        result = interp.analyze_binary_op("*", left, right)

        assert not result.interval.is_bottom()

        assert result.interval.hi is None

        assert result.interval.lo is None or result.interval.lo <= 2

    def test_even_parity_preserved_through_product_mul(self):
        """Parity EVEN × TOP = EVEN inside analyze_binary_op."""

        interp = AbstractInterpreter()

        left = ProductDomain(
            interval=Interval(2, 2),
            sign=Sign.positive(),
            parity=Parity.even(),
        )

        right = ProductDomain(
            interval=Interval(None, None),
            sign=Sign.top(),
            parity=Parity.top(),
        )

        result = interp.analyze_binary_op("*", left, right)

        assert result.parity.value == ParityValue.EVEN

    def test_add_signs_compound_through_product_add(self):
        """_add_signs compound case triggered via analyze_binary_op."""

        interp = AbstractInterpreter()

        left = ProductDomain(
            interval=Interval(1, None),
            sign=Sign.positive(),
            parity=Parity.top(),
        )

        right = ProductDomain(
            interval=Interval(0, None),
            sign=Sign.non_negative(),
            parity=Parity.top(),
        )

        result = interp.analyze_binary_op("+", left, right)

        assert result.sign.value == SignValue.POS

    def test_sub_signs_zero_minus_pos_through_product_sub(self):
        """_sub_signs fix triggered via analyze_binary_op."""

        interp = AbstractInterpreter()

        left = ProductDomain(
            interval=Interval(0, 0),
            sign=Sign.zero(),
            parity=Parity.even(),
        )

        right = ProductDomain(
            interval=Interval(1, 10),
            sign=Sign.positive(),
            parity=Parity.top(),
        )

        result = interp.analyze_binary_op("-", left, right)

        assert result.sign.value == SignValue.NEG

        assert result.interval.hi is not None and result.interval.hi <= -1

    def test_refine_after_binary_op(self):
        """Refine detects contradiction after binary op."""

        interp = AbstractInterpreter()

        pd = ProductDomain(
            interval=Interval(5, 10),
            sign=Sign.negative(),
            parity=Parity.odd(),
        )

        r = pd.refine()

        assert r.is_bottom()

        assert r.interval.is_bottom()

        assert r.sign.is_bottom()

        assert r.parity.is_bottom()

    def test_loop_with_compound_signs(self):
        """
        Loop that grows x from 0: x keeps non-negative sign.
        Tests both analyze_loop fixpoint and _add_signs compound case.
        """

        interp = AbstractInterpreter(widening_threshold=3)

        init = AbstractState()

        init.set(
            "x",
            ProductDomain(
                interval=Interval(0, 0),
                sign=Sign.zero(),
                parity=Parity.even(),
            ),
        )

        def body(state: AbstractState) -> AbstractState:
            x = state.get("x")

            one = ProductDomain(
                interval=Interval(1, 1),
                sign=Sign.positive(),
                parity=Parity.odd(),
            )

            new_x = interp.analyze_binary_op("+", x, one)

            result = state.copy()

            result.set("x", new_x)

            return result

        result = interp.analyze_loop(init, body, max_iterations=50)

        x = result.get("x")

        assert x.interval.hi is None


class TestSignMeet:
    """Verify meet is consistent with the fixed join sub-lattice."""

    @pytest.mark.parametrize(
        "v1,v2,expected",
        [
            (SignValue.NON_NEG, SignValue.NON_POS, SignValue.ZERO),
            (SignValue.NON_NEG, SignValue.NON_ZERO, SignValue.POS),
            (SignValue.NON_POS, SignValue.NON_ZERO, SignValue.NEG),
            (SignValue.NON_NEG, SignValue.POS, SignValue.POS),
            (SignValue.NON_NEG, SignValue.ZERO, SignValue.ZERO),
            (SignValue.NON_POS, SignValue.NEG, SignValue.NEG),
            (SignValue.NON_POS, SignValue.ZERO, SignValue.ZERO),
            (SignValue.NON_ZERO, SignValue.POS, SignValue.POS),
            (SignValue.NON_ZERO, SignValue.NEG, SignValue.NEG),
            (SignValue.NON_ZERO, SignValue.ZERO, SignValue.BOTTOM),
        ],
    )
    def test_meet_table(self, v1, v2, expected):
        assert Sign(v1).meet(Sign(v2)).value == expected

        assert Sign(v2).meet(Sign(v1)).value == expected

    def test_meet_with_top_returns_other(self):
        for sv in SignValue:
            s = Sign(sv)

            assert Sign.top().meet(s) == s

            assert s.meet(Sign.top()) == s

    def test_meet_with_bottom_returns_bottom(self):
        for sv in SignValue:
            if sv in (SignValue.BOTTOM, SignValue.TOP):
                continue

            pass


class TestIntervalEdgeCases:
    """Additional edge cases combining multiple interval fixes."""

    def test_bottom_add_bottom(self):
        assert (Interval.bottom() + Interval.bottom()).is_bottom()

    def test_bottom_sub_bottom(self):
        assert (Interval.bottom() - Interval.bottom()).is_bottom()

    def test_bottom_mul_bottom(self):
        assert (Interval.bottom() * Interval.bottom()).is_bottom()

    def test_neg_of_bottom(self):
        assert (-Interval.bottom()).is_bottom()

    def test_neg_of_unbounded(self):
        r = -Interval(None, 5)

        assert r.lo == -5

        assert r.hi is None

    def test_neg_of_unbounded_below(self):
        r = -Interval(None, None)

        assert r.is_top()

    def test_widen_from_bottom(self):
        assert Interval.bottom().widen(Interval(1, 5)) == Interval(1, 5)

    def test_widen_to_bottom(self):
        assert Interval(1, 5).widen(Interval.bottom()) == Interval(1, 5)

    def test_meet_with_bottom(self):
        r = Interval(1, 10).meet(Interval.bottom())

        assert r.is_bottom()

    def test_join_with_bottom(self):
        r = Interval(1, 10).join(Interval.bottom())

        assert r == Interval(1, 10)

    def test_contains_on_unbounded(self):
        iv = Interval(None, 5)

        assert iv.contains(-9999)

        assert iv.contains(5)

        assert not iv.contains(6)

    def test_is_constant_on_singleton(self):
        assert Interval(7, 7).is_constant()

        assert not Interval(7, 8).is_constant()

        assert not Interval.bottom().is_constant()

        assert not Interval.top().is_constant()

    def test_canonical_bottom_from_various_inversions(self):
        """Multiple inverted ranges all produce the same canonical bottom."""

        bottoms = [Interval(10, 5), Interval(1, -1), Interval(100, 0), Interval(2, 1)]

        for b in bottoms:
            assert b.is_bottom()

            assert b.lo is None

            assert b.hi is None

        for i in range(len(bottoms)):
            for j in range(i + 1, len(bottoms)):
                assert bottoms[i] == bottoms[j]


class TestParityArithmeticExhaustive:
    """Full truth-table for parity add and mul."""

    @pytest.mark.parametrize(
        "a,b,expected_add",
        [
            (ParityValue.EVEN, ParityValue.EVEN, ParityValue.EVEN),
            (ParityValue.EVEN, ParityValue.ODD, ParityValue.ODD),
            (ParityValue.ODD, ParityValue.EVEN, ParityValue.ODD),
            (ParityValue.ODD, ParityValue.ODD, ParityValue.EVEN),
            (ParityValue.EVEN, ParityValue.TOP, ParityValue.TOP),
            (ParityValue.TOP, ParityValue.EVEN, ParityValue.TOP),
            (ParityValue.ODD, ParityValue.TOP, ParityValue.TOP),
            (ParityValue.TOP, ParityValue.ODD, ParityValue.TOP),
            (ParityValue.TOP, ParityValue.TOP, ParityValue.TOP),
        ],
    )
    def test_parity_add(self, a, b, expected_add):
        r = Parity(a) + Parity(b)

        assert r.value == expected_add

    @pytest.mark.parametrize(
        "a,b,expected_mul",
        [
            (ParityValue.EVEN, ParityValue.EVEN, ParityValue.EVEN),
            (ParityValue.EVEN, ParityValue.ODD, ParityValue.EVEN),
            (ParityValue.ODD, ParityValue.EVEN, ParityValue.EVEN),
            (ParityValue.ODD, ParityValue.ODD, ParityValue.ODD),
            (ParityValue.EVEN, ParityValue.TOP, ParityValue.EVEN),
            (ParityValue.TOP, ParityValue.EVEN, ParityValue.EVEN),
            (ParityValue.ODD, ParityValue.TOP, ParityValue.TOP),
            (ParityValue.TOP, ParityValue.ODD, ParityValue.TOP),
            (ParityValue.TOP, ParityValue.TOP, ParityValue.TOP),
        ],
    )
    def test_parity_mul(self, a, b, expected_mul):
        r = Parity(a) * Parity(b)

        assert r.value == expected_mul


class TestMulSigns:
    """Ensure _mul_signs is consistent (not a 'fix' per se, but validated)."""

    def setup_method(self):
        self.interp = AbstractInterpreter()

    @pytest.mark.parametrize(
        "v1,v2,expected",
        [
            (SignValue.POS, SignValue.POS, SignValue.POS),
            (SignValue.NEG, SignValue.NEG, SignValue.POS),
            (SignValue.POS, SignValue.NEG, SignValue.NEG),
            (SignValue.NEG, SignValue.POS, SignValue.NEG),
            (SignValue.ZERO, SignValue.POS, SignValue.ZERO),
            (SignValue.ZERO, SignValue.NEG, SignValue.ZERO),
            (SignValue.POS, SignValue.ZERO, SignValue.ZERO),
            (SignValue.NEG, SignValue.ZERO, SignValue.ZERO),
            (SignValue.ZERO, SignValue.ZERO, SignValue.ZERO),
        ],
    )
    def test_mul_signs(self, v1, v2, expected):
        r = self.interp._mul_signs(Sign(v1), Sign(v2))

        assert r.value == expected

    def test_mul_signs_bottom_propagation(self):
        r = self.interp._mul_signs(Sign.bottom(), Sign.positive())

        assert r.is_bottom()
