import pytest
import pysymex.analysis.abstract.interpreter.values
from pysymex.analysis.abstract.interpreter.values import Sign, SignValue, Interval, Congruence


class ConcreteAbstractValue(pysymex.analysis.abstract.interpreter.values.AbstractValue):
    def is_bottom(self) -> bool:
        return False

    def is_top(self) -> bool:
        return False

    def join(
        self, other: "pysymex.analysis.abstract.interpreter.values.AbstractValue"
    ) -> "pysymex.analysis.abstract.interpreter.values.AbstractValue":
        return self

    def meet(
        self, other: "pysymex.analysis.abstract.interpreter.values.AbstractValue"
    ) -> "pysymex.analysis.abstract.interpreter.values.AbstractValue":
        return self

    def widen(
        self, other: "pysymex.analysis.abstract.interpreter.values.AbstractValue"
    ) -> "pysymex.analysis.abstract.interpreter.values.AbstractValue":
        return self

    def narrow(
        self, other: "pysymex.analysis.abstract.interpreter.values.AbstractValue"
    ) -> "pysymex.analysis.abstract.interpreter.values.AbstractValue":
        return self

    def leq(self, other: "pysymex.analysis.abstract.interpreter.values.AbstractValue") -> bool:
        return True


class TestAbstractValue:
    """Test suite for pysymex.analysis.abstract.interpreter.values.AbstractValue."""

    def test_is_bottom(self) -> None:
        """Test is_bottom behavior."""
        assert ConcreteAbstractValue().is_bottom() is False

    def test_is_top(self) -> None:
        """Test is_top behavior."""
        assert ConcreteAbstractValue().is_top() is False

    def test_join(self) -> None:
        """Test join behavior."""
        val = ConcreteAbstractValue()
        assert val.join(val) is val

    def test_meet(self) -> None:
        """Test meet behavior."""
        val = ConcreteAbstractValue()
        assert val.meet(val) is val

    def test_widen(self) -> None:
        """Test widen behavior."""
        val = ConcreteAbstractValue()
        assert val.widen(val) is val

    def test_narrow(self) -> None:
        """Test narrow behavior."""
        val = ConcreteAbstractValue()
        assert val.narrow(val) is val

    def test_leq(self) -> None:
        """Test leq behavior."""
        val = ConcreteAbstractValue()
        assert val.leq(val) is True


class TestSign:
    """Test suite for pysymex.analysis.abstract.interpreter.values.Sign."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert Sign.BOTTOM.name == "BOTTOM"


class TestSignValue:
    """Test suite for pysymex.analysis.abstract.interpreter.values.SignValue."""

    def test_bottom(self) -> None:
        """Test bottom behavior."""
        assert SignValue.bottom().is_bottom() is True

    def test_top(self) -> None:
        """Test top behavior."""
        assert SignValue.top().is_top() is True

    def test_from_const(self) -> None:
        """Test from_const behavior."""
        assert SignValue.from_const(5).must_be_positive() is True

    def test_is_bottom(self) -> None:
        """Test is_bottom behavior."""
        assert SignValue.bottom().is_bottom() is True

    def test_is_top(self) -> None:
        """Test is_top behavior."""
        assert SignValue.top().is_top() is True

    def test_may_be_zero(self) -> None:
        """Test may_be_zero behavior."""
        assert SignValue.from_const(0).may_be_zero() is True

    def test_must_be_positive(self) -> None:
        """Test must_be_positive behavior."""
        assert SignValue.from_const(5).must_be_positive() is True

    def test_must_be_negative(self) -> None:
        """Test must_be_negative behavior."""
        assert SignValue.from_const(-5).must_be_negative() is True

    def test_must_be_non_zero(self) -> None:
        """Test must_be_non_zero behavior."""
        assert SignValue.from_const(5).must_be_non_zero() is True

    def test_join(self) -> None:
        """Test join behavior."""
        assert SignValue.from_const(1).join(SignValue.from_const(2)).must_be_positive() is True

    def test_meet(self) -> None:
        """Test meet behavior."""
        assert SignValue.from_const(1).meet(SignValue.from_const(-1)).is_bottom() is True

    def test_widen(self) -> None:
        """Test widen behavior."""
        assert SignValue.from_const(1).widen(SignValue.from_const(-1)).must_be_non_zero() is True

    def test_narrow(self) -> None:
        """Test narrow behavior."""
        assert SignValue.from_const(1).narrow(SignValue.from_const(-1)).is_bottom() is True

    def test_leq(self) -> None:
        """Test leq behavior."""
        assert SignValue.from_const(1).leq(SignValue.top()) is True

    def test_add(self) -> None:
        """Test add behavior."""
        assert SignValue.from_const(1).add(SignValue.from_const(2)).must_be_positive() is True

    def test_sub(self) -> None:
        """Test sub behavior."""
        assert SignValue.from_const(1).sub(SignValue.from_const(2)).is_top() is True

    def test_neg(self) -> None:
        """Test neg behavior."""
        assert SignValue.from_const(1).neg().must_be_negative() is True

    def test_mul(self) -> None:
        """Test mul behavior."""
        assert SignValue.from_const(1).mul(SignValue.from_const(-1)).must_be_negative() is True

    def test_div(self) -> None:
        """Test div behavior."""
        res, may_raise = SignValue.from_const(1).div(SignValue.from_const(0))
        assert may_raise is True

    def test_mod(self) -> None:
        """Test mod behavior."""
        res, may_raise = SignValue.from_const(1).mod(SignValue.from_const(0))
        assert may_raise is True


class TestInterval:
    """Test suite for pysymex.analysis.abstract.interpreter.values.Interval."""

    def test_bottom(self) -> None:
        """Test bottom behavior."""
        assert Interval.bottom().is_bottom() is True

    def test_top(self) -> None:
        """Test top behavior."""
        assert Interval.top().is_top() is True

    def test_const(self) -> None:
        """Test const behavior."""
        assert Interval.const(5).is_const() is True

    def test_range(self) -> None:
        """Test range behavior."""
        assert Interval.range(1, 5).low == 1

    def test_non_negative(self) -> None:
        """Test non_negative behavior."""
        assert Interval.non_negative().low == 0

    def test_positive(self) -> None:
        """Test positive behavior."""
        assert Interval.positive().low == 1

    def test_is_bottom(self) -> None:
        """Test is_bottom behavior."""
        assert Interval.bottom().is_bottom() is True

    def test_is_top(self) -> None:
        """Test is_top behavior."""
        assert Interval.top().is_top() is True

    def test_is_const(self) -> None:
        """Test is_const behavior."""
        assert Interval.const(5).is_const() is True

    def test_get_const(self) -> None:
        """Test get_const behavior."""
        assert Interval.const(5).get_const() == 5

    def test_contains(self) -> None:
        """Test contains behavior."""
        assert Interval.const(5).contains(5) is True

    def test_may_be_zero(self) -> None:
        """Test may_be_zero behavior."""
        assert Interval.range(-1, 1).may_be_zero() is True

    def test_must_be_positive(self) -> None:
        """Test must_be_positive behavior."""
        assert Interval.positive().must_be_positive() is True

    def test_must_be_negative(self) -> None:
        """Test must_be_negative behavior."""
        assert Interval.range(-5, -1).must_be_negative() is True

    def test_must_be_non_zero(self) -> None:
        """Test must_be_non_zero behavior."""
        assert Interval.positive().must_be_non_zero() is True

    def test_join(self) -> None:
        """Test join behavior."""
        assert Interval.const(1).join(Interval.const(2)).high == 2

    def test_meet(self) -> None:
        """Test meet behavior."""
        assert Interval.const(1).meet(Interval.const(2)).is_bottom() is True

    def test_widen(self) -> None:
        """Test widen behavior."""
        assert Interval.const(1).widen(Interval.const(2)).high is None

    def test_narrow(self) -> None:
        """Test narrow behavior."""
        assert Interval.const(1).narrow(Interval.const(2)).low == 1

    def test_leq(self) -> None:
        """Test leq behavior."""
        assert Interval.const(1).leq(Interval.top()) is True

    def test_add(self) -> None:
        """Test add behavior."""
        assert Interval.const(1).add(Interval.const(2)).get_const() == 3

    def test_sub(self) -> None:
        """Test sub behavior."""
        assert Interval.const(3).sub(Interval.const(2)).get_const() == 1

    def test_neg(self) -> None:
        """Test neg behavior."""
        assert Interval.const(1).neg().get_const() == -1

    def test_mul(self) -> None:
        """Test mul behavior."""
        assert Interval.const(2).mul(Interval.const(3)).get_const() == 6

    def test_div(self) -> None:
        """Test div behavior."""
        res, may_raise = Interval.const(6).div(Interval.const(2))
        assert res.get_const() == 3

    def test_mod(self) -> None:
        """Test mod behavior."""
        res, may_raise = Interval.const(7).mod(Interval.const(2))
        assert res.get_const() == 1


class TestCongruence:
    """Test suite for pysymex.analysis.abstract.interpreter.values.Congruence."""

    def test_bottom(self) -> None:
        """Test bottom behavior."""
        assert Congruence.bottom().is_bottom() is True

    def test_top(self) -> None:
        """Test top behavior."""
        assert Congruence.top().is_top() is True

    def test_const(self) -> None:
        """Test const behavior."""
        assert Congruence.const(5).is_const() is True

    def test_mod(self) -> None:
        """Test mod behavior."""
        assert Congruence.mod(2, 1).modulus == 2

    def test_is_bottom(self) -> None:
        """Test is_bottom behavior."""
        assert Congruence.bottom().is_bottom() is True

    def test_is_top(self) -> None:
        """Test is_top behavior."""
        assert Congruence.top().is_top() is True

    def test_is_const(self) -> None:
        """Test is_const behavior."""
        assert Congruence.const(5).is_const() is True

    def test_get_const(self) -> None:
        """Test get_const behavior."""
        assert Congruence.const(5).get_const() == 5

    def test_may_be_zero(self) -> None:
        """Test may_be_zero behavior."""
        assert Congruence.top().may_be_zero() is True

    def test_must_be_even(self) -> None:
        """Test must_be_even behavior."""
        assert Congruence.const(2).must_be_even() is True

    def test_join(self) -> None:
        """Test join behavior."""
        assert Congruence.const(2).join(Congruence.const(4)).modulus == 2

    def test_meet(self) -> None:
        """Test meet behavior."""
        assert Congruence.const(2).meet(Congruence.const(3)).is_bottom() is True

    def test_widen(self) -> None:
        """Test widen behavior."""
        assert Congruence.const(2).widen(Congruence.const(4)).modulus == 2

    def test_narrow(self) -> None:
        """Test narrow behavior."""
        assert Congruence.const(2).narrow(Congruence.const(4)).is_bottom() is True

    def test_leq(self) -> None:
        """Test leq behavior."""
        assert Congruence.const(2).leq(Congruence.top()) is True
