import pytest
from unittest.mock import Mock, patch
import z3
from pysymex.analysis.specialized.ranges import (
    Range, RangeState, RangeWarning, RangeAnalyzer, ValueRangeChecker
)

class TestRange:
    """Test suite for pysymex.analysis.specialized.ranges.Range."""
    def test_empty(self) -> None:
        """Test empty behavior."""
        r = Range.empty()
        assert r.is_empty is True

    def test_full(self) -> None:
        """Test full behavior."""
        r = Range.full()
        assert r.is_full() is True

    def test_exact(self) -> None:
        """Test exact behavior."""
        r = Range.exact(5)
        assert r.is_exact is True
        assert r.exact_value == 5

    def test_at_least(self) -> None:
        """Test at_least behavior."""
        r = Range.at_least(5)
        assert r.low == 5
        assert r.high is None

    def test_at_most(self) -> None:
        """Test at_most behavior."""
        r = Range.at_most(5)
        assert r.low is None
        assert r.high == 5

    def test_between(self) -> None:
        """Test between behavior."""
        r = Range.between(1, 5)
        assert r.low == 1
        assert r.high == 5

    def test_is_full(self) -> None:
        """Test is_full behavior."""
        assert Range.full().is_full() is True

    def test_is_exact(self) -> None:
        """Test is_exact behavior."""
        assert Range.exact(5).is_exact is True

    def test_exact_value(self) -> None:
        """Test exact_value behavior."""
        assert Range.exact(5).exact_value == 5
        assert Range.full().exact_value is None

    def test_contains(self) -> None:
        """Test contains behavior."""
        r = Range.between(1, 5)
        assert r.contains(3) is True
        assert r.contains(6) is False

    def test_may_be_zero(self) -> None:
        """Test may_be_zero behavior."""
        assert Range.between(-1, 1).may_be_zero() is True
        assert Range.between(1, 5).may_be_zero() is False

    def test_must_be_positive(self) -> None:
        """Test must_be_positive behavior."""
        assert Range.at_least(1).must_be_positive() is True
        assert Range.full().must_be_positive() is False

    def test_must_be_negative(self) -> None:
        """Test must_be_negative behavior."""
        assert Range.at_most(-1).must_be_negative() is True

    def test_must_be_non_negative(self) -> None:
        """Test must_be_non_negative behavior."""
        assert Range.at_least(0).must_be_non_negative() is True

    def test_must_be_non_positive(self) -> None:
        """Test must_be_non_positive behavior."""
        assert Range.at_most(0).must_be_non_positive() is True

    def test_must_be_non_zero(self) -> None:
        """Test must_be_non_zero behavior."""
        assert Range.exact(5).must_be_non_zero() is True
        assert Range.full().must_be_non_zero() is False

    def test_union(self) -> None:
        """Test union behavior."""
        r1 = Range.between(1, 5)
        r2 = Range.between(4, 10)
        u = r1.union(r2)
        assert u.low == 1 and u.high == 10

    def test_intersect(self) -> None:
        """Test intersect behavior."""
        r1 = Range.between(1, 5)
        r2 = Range.between(4, 10)
        i = r1.intersect(r2)
        assert i.low == 4 and i.high == 5
        
        r3 = Range.between(10, 20)
        assert r1.intersect(r3).is_empty is True

    def test_widen(self) -> None:
        """Test widen behavior."""
        r1 = Range.between(1, 5)
        r2 = Range.between(1, 10)
        w = r1.widen(r2)
        assert w.low == 1 and w.high is None

    def test_narrow(self) -> None:
        """Test narrow behavior."""
        r1 = Range.at_least(1)
        r2 = Range.between(1, 10)
        n = r1.narrow(r2)
        assert n.low == 1 and n.high == 10

    def test_subset_of(self) -> None:
        """Test subset_of behavior."""
        assert Range.between(2, 4).subset_of(Range.between(1, 5)) is True
        assert Range.between(0, 4).subset_of(Range.between(1, 5)) is False

    def test_add(self) -> None:
        """Test add behavior."""
        assert Range.exact(2).add(Range.exact(3)).exact_value == 5

    def test_sub(self) -> None:
        """Test sub behavior."""
        assert Range.exact(5).sub(Range.exact(3)).exact_value == 2

    def test_neg(self) -> None:
        """Test neg behavior."""
        assert Range.exact(5).neg().exact_value == -5

    def test_mul(self) -> None:
        """Test mul behavior."""
        assert Range.exact(2).mul(Range.exact(3)).exact_value == 6

    def test_div(self) -> None:
        """Test div behavior."""
        res, may_raise = Range.exact(6).div(Range.exact(2))
        assert res.exact_value == 3

    def test_mod(self) -> None:
        """Test mod behavior."""
        res, may_raise = Range.exact(7).mod(Range.exact(2))
        assert res.low == 0 and res.high == 1

class TestRangeState:
    """Test suite for pysymex.analysis.specialized.ranges.RangeState."""
    def test_bottom(self) -> None:
        """Test bottom behavior."""
        assert RangeState.bottom().is_bottom is True

    def test_top(self) -> None:
        """Test top behavior."""
        assert RangeState.top().is_bottom is False

    def test_copy(self) -> None:
        """Test copy behavior."""
        s = RangeState()
        s.set("x", Range.exact(5))
        c = s.copy()
        assert c.get("x").exact_value == 5
        assert c is not s

    def test_get(self) -> None:
        """Test get behavior."""
        s = RangeState()
        assert s.get("x").is_full() is True

    def test_set(self) -> None:
        """Test set behavior."""
        s = RangeState()
        s.set("x", Range.exact(5))
        assert s.get("x").exact_value == 5

    def test_push(self) -> None:
        """Test push behavior."""
        s = RangeState()
        s.push(Range.exact(5))
        assert len(s.stack) == 1

    def test_pop(self) -> None:
        """Test pop behavior."""
        s = RangeState()
        s.push(Range.exact(5))
        assert s.pop().exact_value == 5

    def test_peek(self) -> None:
        """Test peek behavior."""
        s = RangeState()
        s.push(Range.exact(5))
        assert s.peek().exact_value == 5

    def test_join(self) -> None:
        """Test join behavior."""
        s1 = RangeState()
        s1.set("x", Range.exact(1))
        s2 = RangeState()
        s2.set("x", Range.exact(2))
        j = s1.join(s2)
        r = j.get("x")
        assert r.low == 1 and r.high == 2

    def test_widen(self) -> None:
        """Test widen behavior."""
        s1 = RangeState()
        s1.set("x", Range.exact(1))
        s2 = RangeState()
        s2.set("x", Range.between(1, 2))
        w = s1.widen(s2)
        assert w.get("x").high is None

    def test_subset_of(self) -> None:
        """Test subset_of behavior."""
        s1 = RangeState()
        s1.set("x", Range.exact(1))
        s2 = RangeState.top()
        assert s1.subset_of(s2) is True

class TestRangeWarning:
    """Test suite for pysymex.analysis.specialized.ranges.RangeWarning."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        w = RangeWarning(10, 5, "OOB", "msg")
        assert w.kind == "OOB"

class TestRangeAnalyzer:
    """Test suite for pysymex.analysis.specialized.ranges.RangeAnalyzer."""
    @patch("pysymex.analysis.specialized.ranges.CFGBuilder")
    def test_analyze(self, mock_cfg_builder) -> None:
        """Test analyze behavior."""
        mock_cfg = Mock()
        mock_cfg.blocks = {}
        mock_cfg_builder.return_value.build.return_value = mock_cfg
        analyzer = RangeAnalyzer()
        warnings = analyzer.analyze(Mock(co_firstlineno=1)) # type: ignore[arg-type]
        assert isinstance(warnings, tuple)
        assert isinstance(warnings[1], list)

class TestValueRangeChecker:
    """Test suite for pysymex.analysis.specialized.ranges.ValueRangeChecker."""
    @patch("pysymex.analysis.specialized.ranges.CFGBuilder")
    def test_check_function(self, mock_cfg_builder) -> None:
        """Test check_function behavior."""
        mock_cfg = Mock()
        mock_cfg.blocks = {}
        mock_cfg_builder.return_value.build.return_value = mock_cfg
        c = ValueRangeChecker()
        res = c.check_function(Mock(co_firstlineno=1)) # type: ignore[arg-type]
        assert isinstance(res, list)

    def test_check_array_bounds(self) -> None:
        """Test check_array_bounds behavior."""
        c = ValueRangeChecker()
        res = c.check_array_bounds(Range.exact(5), 4)
        assert res is not None
        assert "may be out of bounds" in res
