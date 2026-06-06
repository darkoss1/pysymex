from pysymex.analysis.domains.ranges.domain import Range
from pysymex.analysis.domains.ranges.state import RangeState
from pysymex.analysis.domains.ranges.warnings import RangeWarning


class TestRangeState:
    """Test suite for pysymex.analysis.domains.ranges.RangeState."""

    def test_bottom(self) -> None:
        assert RangeState.bottom().is_bottom is True

    def test_top(self) -> None:
        assert RangeState.top().is_bottom is False

    def test_copy(self) -> None:
        s = RangeState()
        s.set("x", Range.exact(5))
        c = s.copy()
        assert c.get("x").exact_value == 5
        assert c is not s

    def test_get(self) -> None:
        s = RangeState()
        assert s.get("x").is_full() is True

    def test_set(self) -> None:
        s = RangeState()
        s.set("x", Range.exact(5))
        assert s.get("x").exact_value == 5

    def test_push(self) -> None:
        s = RangeState()
        s.push(Range.exact(5))
        assert len(s.stack) == 1

    def test_pop(self) -> None:
        s = RangeState()
        s.push(Range.exact(5))
        assert s.pop().exact_value == 5

    def test_peek(self) -> None:
        s = RangeState()
        s.push(Range.exact(5))
        assert s.peek().exact_value == 5

    def test_join(self) -> None:
        s1 = RangeState()
        s1.set("x", Range.exact(1))
        s2 = RangeState()
        s2.set("x", Range.exact(2))
        r = s1.join(s2).get("x")
        assert r.low == 1 and r.high == 2

    def test_widen(self) -> None:
        s1 = RangeState()
        s1.set("x", Range.exact(1))
        s2 = RangeState()
        s2.set("x", Range.between(1, 2))
        assert s1.widen(s2).get("x").high is None

    def test_subset_of(self) -> None:
        s1 = RangeState()
        s1.set("x", Range.exact(1))
        assert s1.subset_of(RangeState.top()) is True


class TestRangeWarning:
    """Test suite for pysymex.analysis.domains.ranges.RangeWarning."""

    def test_initialization(self) -> None:
        w = RangeWarning(10, 5, "OOB", "msg")
        assert w.kind == "OOB"
