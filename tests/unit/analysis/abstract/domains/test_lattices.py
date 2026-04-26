import z3
from pysymex.analysis.abstract.domains.lattices import (
    Sign,
    SignValue,
    Parity,
    ParityValue,
    Null,
    NullValue,
)


class TestSignValue:
    """Test suite for pysymex.analysis.abstract.domains.lattices.SignValue."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert SignValue.BOTTOM.name == "BOTTOM"


class TestSign:
    """Test suite for pysymex.analysis.abstract.domains.lattices.Sign."""

    def test_is_top(self) -> None:
        """Test is_top behavior."""
        assert Sign.top().is_top() is True
        assert Sign.bottom().is_top() is False

    def test_is_bottom(self) -> None:
        """Test is_bottom behavior."""
        assert Sign.bottom().is_bottom() is True
        assert Sign.top().is_bottom() is False

    def test_join(self) -> None:
        """Test join behavior."""
        s1 = Sign(SignValue.POS)
        s2 = Sign(SignValue.ZERO)
        joined = s1.join(s2)
        assert joined.value == SignValue.NON_NEG

    def test_meet(self) -> None:
        """Test meet behavior."""
        s1 = Sign(SignValue.NON_NEG)
        s2 = Sign(SignValue.NON_POS)
        met = s1.meet(s2)
        assert met.value == SignValue.ZERO

    def test_widen(self) -> None:
        """Test widen behavior."""
        s1 = Sign(SignValue.POS)
        s2 = Sign(SignValue.NEG)
        widened = s1.widen(s2)
        assert widened.value == SignValue.NON_ZERO

    def test_to_z3_constraint(self) -> None:
        """Test to_z3_constraint behavior."""
        var = z3.Int("x")
        bot_constraint = Sign.bottom().to_z3_constraint(var)
        assert z3.is_false(bot_constraint)
        top_constraint = Sign.top().to_z3_constraint(var)
        assert z3.is_true(top_constraint)

    def test_from_concrete(self) -> None:
        """Test from_concrete behavior."""
        pos = Sign.from_concrete(5)
        assert pos.value == SignValue.POS
        zero = Sign.from_concrete(0)
        assert zero.value == SignValue.ZERO
        neg = Sign.from_concrete(-5)
        assert neg.value == SignValue.NEG

    def test_top(self) -> None:
        """Test top behavior."""
        assert Sign.top().value == SignValue.TOP

    def test_bottom(self) -> None:
        """Test bottom behavior."""
        assert Sign.bottom().value == SignValue.BOTTOM

    def test_positive(self) -> None:
        """Test positive behavior."""
        assert Sign.positive().value == SignValue.POS

    def test_negative(self) -> None:
        """Test negative behavior."""
        assert Sign.negative().value == SignValue.NEG

    def test_zero(self) -> None:
        """Test zero behavior."""
        assert Sign.zero().value == SignValue.ZERO

    def test_non_negative(self) -> None:
        """Test non_negative behavior."""
        assert Sign.non_negative().value == SignValue.NON_NEG

    def test_non_positive(self) -> None:
        """Test non_positive behavior."""
        assert Sign.non_positive().value == SignValue.NON_POS

    def test_non_zero(self) -> None:
        """Test non_zero behavior."""
        assert Sign.non_zero().value == SignValue.NON_ZERO


class TestParityValue:
    """Test suite for pysymex.analysis.abstract.domains.lattices.ParityValue."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert ParityValue.BOTTOM.name == "BOTTOM"


class TestParity:
    """Test suite for pysymex.analysis.abstract.domains.lattices.Parity."""

    def test_is_top(self) -> None:
        """Test is_top behavior."""
        assert Parity.top().is_top() is True
        assert Parity.even().is_top() is False

    def test_is_bottom(self) -> None:
        """Test is_bottom behavior."""
        assert Parity.bottom().is_bottom() is True
        assert Parity.top().is_bottom() is False

    def test_join(self) -> None:
        """Test join behavior."""
        p1 = Parity.even()
        p2 = Parity.odd()
        assert p1.join(p2).is_top() is True

    def test_meet(self) -> None:
        """Test meet behavior."""
        p1 = Parity.even()
        p2 = Parity.odd()
        assert p1.meet(p2).is_bottom() is True

    def test_widen(self) -> None:
        """Test widen behavior."""
        p1 = Parity.even()
        p2 = Parity.odd()
        assert p1.widen(p2).is_top() is True

    def test_to_z3_constraint(self) -> None:
        """Test to_z3_constraint behavior."""
        var = z3.Int("x")
        bot_constraint = Parity.bottom().to_z3_constraint(var)
        assert z3.is_false(bot_constraint)

    def test_from_concrete(self) -> None:
        """Test from_concrete behavior."""
        assert Parity.from_concrete(2).value == ParityValue.EVEN
        assert Parity.from_concrete(3).value == ParityValue.ODD

    def test_top(self) -> None:
        """Test top behavior."""
        assert Parity.top().value == ParityValue.TOP

    def test_bottom(self) -> None:
        """Test bottom behavior."""
        assert Parity.bottom().value == ParityValue.BOTTOM

    def test_even(self) -> None:
        """Test even behavior."""
        assert Parity.even().value == ParityValue.EVEN

    def test_odd(self) -> None:
        """Test odd behavior."""
        assert Parity.odd().value == ParityValue.ODD


class TestNullValue:
    """Test suite for pysymex.analysis.abstract.domains.lattices.NullValue."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert NullValue.BOTTOM.name == "BOTTOM"


class TestNull:
    """Test suite for pysymex.analysis.abstract.domains.lattices.Null."""

    def test_is_top(self) -> None:
        """Test is_top behavior."""
        assert Null.top().is_top() is True
        assert Null.null().is_top() is False

    def test_is_bottom(self) -> None:
        """Test is_bottom behavior."""
        assert Null.bottom().is_bottom() is True
        assert Null.top().is_bottom() is False

    def test_is_null(self) -> None:
        """Test is_null behavior."""
        assert Null.null().is_null() is True
        assert Null.top().is_null() is False

    def test_is_non_null(self) -> None:
        """Test is_non_null behavior."""
        assert Null.non_null().is_non_null() is True
        assert Null.top().is_non_null() is False

    def test_may_be_null(self) -> None:
        """Test may_be_null behavior."""
        assert Null.top().may_be_null() is True
        assert Null.null().may_be_null() is True
        assert Null.non_null().may_be_null() is False

    def test_join(self) -> None:
        """Test join behavior."""
        n1 = Null.null()
        n2 = Null.non_null()
        assert n1.join(n2).is_top() is True

    def test_meet(self) -> None:
        """Test meet behavior."""
        n1 = Null.null()
        n2 = Null.non_null()
        assert n1.meet(n2).is_bottom() is True

    def test_widen(self) -> None:
        """Test widen behavior."""
        n1 = Null.null()
        n2 = Null.non_null()
        assert n1.widen(n2).is_top() is True

    def test_to_z3_constraint(self) -> None:
        """Test to_z3_constraint behavior."""
        var = z3.Int("x")
        bot_constraint = Null.bottom().to_z3_constraint(var)
        assert z3.is_false(bot_constraint)

    def test_from_concrete(self) -> None:
        """Test from_concrete behavior."""
        assert Null.from_concrete(None).value == NullValue.NULL
        assert Null.from_concrete(42).value == NullValue.NON_NULL

    def test_top(self) -> None:
        """Test top behavior."""
        assert Null.top().value == NullValue.TOP

    def test_bottom(self) -> None:
        """Test bottom behavior."""
        assert Null.bottom().value == NullValue.BOTTOM

    def test_null(self) -> None:
        """Test null behavior."""
        assert Null.null().value == NullValue.NULL

    def test_non_null(self) -> None:
        """Test non_null behavior."""
        assert Null.non_null().value == NullValue.NON_NULL
