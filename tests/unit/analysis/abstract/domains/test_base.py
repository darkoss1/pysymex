import z3
import pytest
from typing import TypeVar
from pysymex.analysis.abstract.domains.base import AbstractValue, Interval

T = TypeVar("T")


class ConcreteValue(AbstractValue["ConcreteValue"]):
    def is_top(self) -> bool:
        return False

    def is_bottom(self) -> bool:
        return False

    def join(self, other: "ConcreteValue") -> "ConcreteValue":
        return self

    def meet(self, other: "ConcreteValue") -> "ConcreteValue":
        return self

    def widen(self, other: "ConcreteValue") -> "ConcreteValue":
        return self

    def to_z3_constraint(self, var: z3.ExprRef) -> z3.BoolRef:
        return z3.BoolVal(True)

    @classmethod
    def from_concrete(cls, value: object) -> "ConcreteValue":
        return cls()

    @classmethod
    def top(cls) -> "ConcreteValue":
        return cls()

    @classmethod
    def bottom(cls) -> "ConcreteValue":
        return cls()


class TestAbstractValue:
    """Test suite for pysymex.analysis.abstract.domains.base.AbstractValue."""

    def test_is_top(self) -> None:
        """Test is_top behavior on concrete subclass."""
        val = ConcreteValue()
        assert val.is_top() is False

    def test_is_bottom(self) -> None:
        """Test is_bottom behavior on concrete subclass."""
        val = ConcreteValue()
        assert val.is_bottom() is False

    def test_join(self) -> None:
        """Test join behavior on concrete subclass."""
        val = ConcreteValue()
        assert val.join(val) is val

    def test_meet(self) -> None:
        """Test meet behavior on concrete subclass."""
        val = ConcreteValue()
        assert val.meet(val) is val

    def test_widen(self) -> None:
        """Test widen behavior on concrete subclass."""
        val = ConcreteValue()
        assert val.widen(val) is val

    def test_to_z3_constraint(self) -> None:
        """Test to_z3_constraint behavior on concrete subclass."""
        val = ConcreteValue()
        var = z3.Int("x")
        assert z3.is_true(val.to_z3_constraint(var))

    def test_from_concrete(self) -> None:
        """Test from_concrete behavior on concrete subclass."""
        val = ConcreteValue.from_concrete(1)
        assert isinstance(val, ConcreteValue)

    def test_top(self) -> None:
        """Test top behavior on concrete subclass."""
        val = ConcreteValue.top()
        assert isinstance(val, ConcreteValue)

    def test_bottom(self) -> None:
        """Test bottom behavior on concrete subclass."""
        val = ConcreteValue.bottom()
        assert isinstance(val, ConcreteValue)


class TestInterval:
    """Test suite for pysymex.analysis.abstract.domains.base.Interval."""

    def test_is_top(self) -> None:
        """Test is_top behavior."""
        top_val = Interval.top()
        assert top_val.is_top() is True
        assert Interval(0, 10).is_top() is False

    def test_is_bottom(self) -> None:
        """Test is_bottom behavior."""
        bot_val = Interval.bottom()
        assert bot_val.is_bottom() is True
        assert Interval(0, 10).is_bottom() is False
        assert Interval(10, 0).is_bottom() is True

    def test_is_constant(self) -> None:
        """Test is_constant behavior."""
        assert Interval(5, 5).is_constant() is True
        assert Interval(0, 10).is_constant() is False
        assert Interval.bottom().is_constant() is False

    def test_contains(self) -> None:
        """Test contains behavior."""
        interval = Interval(0, 10)
        assert interval.contains(5) is True
        assert interval.contains(-1) is False
        assert interval.contains(11) is False
        assert Interval.bottom().contains(5) is False
        assert Interval.at_least(5).contains(10) is True
        assert Interval.at_most(5).contains(0) is True

    def test_join(self) -> None:
        """Test join behavior."""
        i1 = Interval(0, 5)
        i2 = Interval(3, 10)
        joined = i1.join(i2)
        assert joined.lo == 0 and joined.hi == 10
        assert i1.join(Interval.bottom()) == i1
        assert Interval.bottom().join(i2) == i2

    def test_meet(self) -> None:
        """Test meet behavior."""
        i1 = Interval(0, 5)
        i2 = Interval(3, 10)
        met = i1.meet(i2)
        assert met.lo == 3 and met.hi == 5
        assert i1.meet(Interval.bottom()).is_bottom() is True
        assert Interval(0, 5).meet(Interval(10, 20)).is_bottom() is True

    def test_widen(self) -> None:
        """Test widen behavior."""
        i1 = Interval(0, 5)
        i2 = Interval(0, 10)
        widened = i1.widen(i2)
        assert widened.lo == 0 and widened.hi is None
        bot = Interval.bottom()
        assert bot.widen(i1) == i1
        assert i1.widen(bot) == i1

    def test_to_z3_constraint(self) -> None:
        """Test to_z3_constraint behavior."""
        var = z3.Int("x")
        bot_constraint = Interval.bottom().to_z3_constraint(var)
        assert z3.is_false(bot_constraint)
        top_constraint = Interval.top().to_z3_constraint(var)
        assert z3.is_true(top_constraint)
        mid_constraint = Interval(0, 10).to_z3_constraint(var)
        assert not z3.is_true(mid_constraint) and not z3.is_false(mid_constraint)

    def test_from_concrete(self) -> None:
        """Test from_concrete behavior."""
        val = Interval.from_concrete(5)
        assert val.lo == 5 and val.hi == 5
        with pytest.raises(TypeError):
            Interval.from_concrete("not int")

    def test_top(self) -> None:
        """Test top behavior."""
        val = Interval.top()
        assert val.lo is None and val.hi is None

    def test_bottom(self) -> None:
        """Test bottom behavior."""
        val = Interval.bottom()
        assert val.is_bottom() is True

    def test_range(self) -> None:
        """Test range behavior."""
        val = Interval.range(2, 8)
        assert val.lo == 2 and val.hi == 8

    def test_at_least(self) -> None:
        """Test at_least behavior."""
        val = Interval.at_least(5)
        assert val.lo == 5 and val.hi is None

    def test_at_most(self) -> None:
        """Test at_most behavior."""
        val = Interval.at_most(5)
        assert val.lo is None and val.hi == 5
