import pytest
import pysymex.analysis.abstract.interpreter.state
from pysymex.analysis.abstract.interpreter.values import Interval, SignValue, Congruence

class TestNumericProduct:
    """Test suite for pysymex.analysis.abstract.interpreter.state.NumericProduct."""
    def test_bottom(self) -> None:
        """Test bottom behavior."""
        val = pysymex.analysis.abstract.interpreter.state.NumericProduct.bottom()
        assert val.is_bottom() is True

    def test_top(self) -> None:
        """Test top behavior."""
        val = pysymex.analysis.abstract.interpreter.state.NumericProduct.top()
        assert val.is_top() is True

    def test_const(self) -> None:
        """Test const behavior."""
        val = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(5)
        assert val.interval.get_const() == 5

    def test_reduce(self) -> None:
        """Test reduce behavior."""
        val = pysymex.analysis.abstract.interpreter.state.NumericProduct(
            Interval.range(1, 10), SignValue.top(), Congruence.top()
        )
        reduced = val.reduce()
        assert reduced.sign.must_be_positive() is True

    def test_is_bottom(self) -> None:
        """Test is_bottom behavior."""
        assert pysymex.analysis.abstract.interpreter.state.NumericProduct.bottom().is_bottom() is True

    def test_is_top(self) -> None:
        """Test is_top behavior."""
        assert pysymex.analysis.abstract.interpreter.state.NumericProduct.top().is_top() is True

    def test_may_be_zero(self) -> None:
        """Test may_be_zero behavior."""
        val = pysymex.analysis.abstract.interpreter.state.NumericProduct.top()
        assert val.may_be_zero() is True

    def test_must_be_non_zero(self) -> None:
        """Test must_be_non_zero behavior."""
        val = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(5)
        assert val.must_be_non_zero() is True

    def test_join(self) -> None:
        """Test join behavior."""
        v1 = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(1)
        v2 = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(2)
        joined = v1.join(v2)
        assert joined.interval.low == 1 and joined.interval.high == 2

    def test_meet(self) -> None:
        """Test meet behavior."""
        v1 = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(1)
        v2 = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(2)
        assert v1.meet(v2).is_bottom() is True

    def test_widen(self) -> None:
        """Test widen behavior."""
        v1 = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(1)
        v2 = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(2)
        assert v1.widen(v2).interval.high is None

    def test_narrow(self) -> None:
        """Test narrow behavior."""
        v1 = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(1)
        v2 = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(2)
        assert v1.narrow(v2).is_bottom() is True

    def test_leq(self) -> None:
        """Test leq behavior."""
        v1 = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(1)
        top = pysymex.analysis.abstract.interpreter.state.NumericProduct.top()
        assert v1.leq(top) is True

    def test_add(self) -> None:
        """Test add behavior."""
        v1 = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(1)
        v2 = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(2)
        assert v1.add(v2).interval.get_const() == 3

    def test_sub(self) -> None:
        """Test sub behavior."""
        v1 = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(3)
        v2 = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(2)
        assert v1.sub(v2).interval.get_const() == 1

    def test_mul(self) -> None:
        """Test mul behavior."""
        v1 = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(3)
        v2 = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(2)
        assert v1.mul(v2).interval.get_const() == 6

    def test_div(self) -> None:
        """Test div behavior."""
        v1 = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(6)
        v2 = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(2)
        res, raises = v1.div(v2)
        assert res.interval.get_const() == 3
        assert raises is False

    def test_mod(self) -> None:
        """Test mod behavior."""
        v1 = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(7)
        v2 = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(2)
        res, raises = v1.mod(v2)
        assert res.interval.get_const() == 1
        assert raises is False

class TestAbstractState:
    """Test suite for pysymex.analysis.abstract.interpreter.state.AbstractState."""
    def test_bottom(self) -> None:
        """Test bottom behavior."""
        state = pysymex.analysis.abstract.interpreter.state.AbstractState.bottom()
        assert state.is_bottom() is True

    def test_top(self) -> None:
        """Test top behavior."""
        state = pysymex.analysis.abstract.interpreter.state.AbstractState.top()
        assert state.is_bottom() is False

    def test_copy(self) -> None:
        """Test copy behavior."""
        state = pysymex.analysis.abstract.interpreter.state.AbstractState()
        val = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(5)
        state.set("x", val)
        c = state.copy()
        assert c.get("x").interval.get_const() == 5

    def test_is_bottom(self) -> None:
        """Test is_bottom behavior."""
        state = pysymex.analysis.abstract.interpreter.state.AbstractState.bottom()
        assert state.is_bottom() is True

    def test_get(self) -> None:
        """Test get behavior."""
        state = pysymex.analysis.abstract.interpreter.state.AbstractState()
        assert state.get("unknown").is_top() is True

    def test_set(self) -> None:
        """Test set behavior."""
        state = pysymex.analysis.abstract.interpreter.state.AbstractState()
        state.set("x", pysymex.analysis.abstract.interpreter.state.NumericProduct.bottom())
        assert state.is_bottom() is True

    def test_push(self) -> None:
        """Test push behavior."""
        state = pysymex.analysis.abstract.interpreter.state.AbstractState()
        val = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(5)
        state.push(val)
        assert len(state.stack) == 1

    def test_pop(self) -> None:
        """Test pop behavior."""
        state = pysymex.analysis.abstract.interpreter.state.AbstractState()
        val = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(5)
        state.push(val)
        assert state.pop().interval.get_const() == 5

    def test_peek(self) -> None:
        """Test peek behavior."""
        state = pysymex.analysis.abstract.interpreter.state.AbstractState()
        val = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(5)
        state.push(val)
        assert state.peek().interval.get_const() == 5

    def test_join(self) -> None:
        """Test join behavior."""
        s1 = pysymex.analysis.abstract.interpreter.state.AbstractState()
        s1.set("x", pysymex.analysis.abstract.interpreter.state.NumericProduct.const(1))
        s2 = pysymex.analysis.abstract.interpreter.state.AbstractState()
        s2.set("x", pysymex.analysis.abstract.interpreter.state.NumericProduct.const(2))
        joined = s1.join(s2)
        assert joined.get("x").interval.low == 1

    def test_widen(self) -> None:
        """Test widen behavior."""
        s1 = pysymex.analysis.abstract.interpreter.state.AbstractState()
        s1.set("x", pysymex.analysis.abstract.interpreter.state.NumericProduct.const(1))
        s2 = pysymex.analysis.abstract.interpreter.state.AbstractState()
        s2.set("x", pysymex.analysis.abstract.interpreter.state.NumericProduct.const(2))
        widened = s1.widen(s2)
        assert widened.get("x").interval.high is None

    def test_leq(self) -> None:
        """Test leq behavior."""
        s1 = pysymex.analysis.abstract.interpreter.state.AbstractState()
        s2 = pysymex.analysis.abstract.interpreter.state.AbstractState.top()
        assert s1.leq(s2) is True

class TestAbstractWarning:
    """Test suite for pysymex.analysis.abstract.interpreter.state.AbstractWarning."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        warning = pysymex.analysis.abstract.interpreter.state.AbstractWarning("kind", "msg", "file", 1)
        assert warning.kind == "kind"

class TestDivisionByZeroWarning:
    """Test suite for pysymex.analysis.abstract.interpreter.state.DivisionByZeroWarning."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        val = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(0)
        warning = pysymex.analysis.abstract.interpreter.state.DivisionByZeroWarning(1, 0, "x", val, "high")
        assert warning.variable == "x"

class TestIndexOutOfBoundsWarning:
    """Test suite for pysymex.analysis.abstract.interpreter.state.IndexOutOfBoundsWarning."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        idx = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(5)
        sz = pysymex.analysis.abstract.interpreter.state.NumericProduct.const(5)
        warning = pysymex.analysis.abstract.interpreter.state.IndexOutOfBoundsWarning(1, 0, "arr", idx, sz)
        assert warning.collection == "arr"
