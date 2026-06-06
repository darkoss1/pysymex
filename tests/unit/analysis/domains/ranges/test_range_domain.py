from pysymex.analysis.domains.ranges.domain import Range


class TestRange:
    """Test suite for pysymex.analysis.domains.ranges.Range."""

    def test_empty(self) -> None:
        r = Range.empty()
        assert r.is_empty is True

    def test_full(self) -> None:
        r = Range.full()
        assert r.is_full() is True

    def test_exact(self) -> None:
        r = Range.exact(5)
        assert r.is_exact is True
        assert r.exact_value == 5

    def test_at_least(self) -> None:
        r = Range.at_least(5)
        assert r.low == 5
        assert r.high is None

    def test_at_most(self) -> None:
        r = Range.at_most(5)
        assert r.low is None
        assert r.high == 5

    def test_between(self) -> None:
        r = Range.between(1, 5)
        assert r.low == 1
        assert r.high == 5

    def test_is_full(self) -> None:
        assert Range.full().is_full() is True

    def test_is_exact(self) -> None:
        assert Range.exact(5).is_exact is True

    def test_exact_value(self) -> None:
        assert Range.exact(5).exact_value == 5
        assert Range.full().exact_value is None

    def test_contains(self) -> None:
        r = Range.between(1, 5)
        assert r.contains(3) is True
        assert r.contains(6) is False

    def test_may_be_zero(self) -> None:
        assert Range.between(-1, 1).may_be_zero() is True
        assert Range.between(1, 5).may_be_zero() is False

    def test_must_be_positive(self) -> None:
        assert Range.at_least(1).must_be_positive() is True
        assert Range.full().must_be_positive() is False

    def test_must_be_negative(self) -> None:
        assert Range.at_most(-1).must_be_negative() is True

    def test_must_be_non_negative(self) -> None:
        assert Range.at_least(0).must_be_non_negative() is True

    def test_must_be_non_positive(self) -> None:
        assert Range.at_most(0).must_be_non_positive() is True

    def test_must_be_non_zero(self) -> None:
        assert Range.exact(5).must_be_non_zero() is True
        assert Range.full().must_be_non_zero() is False

    def test_union(self) -> None:
        r1 = Range.between(1, 5)
        r2 = Range.between(4, 10)
        u = r1.union(r2)
        assert u.low == 1 and u.high == 10

    def test_intersect(self) -> None:
        r1 = Range.between(1, 5)
        r2 = Range.between(4, 10)
        i = r1.intersect(r2)
        assert i.low == 4 and i.high == 5
        assert r1.intersect(Range.between(10, 20)).is_empty is True

    def test_widen(self) -> None:
        r1 = Range.between(1, 5)
        r2 = Range.between(1, 10)
        w = r1.widen(r2)
        assert w.low == 1 and w.high is None

    def test_narrow(self) -> None:
        r1 = Range.at_least(1)
        r2 = Range.between(1, 10)
        n = r1.narrow(r2)
        assert n.low == 1 and n.high == 10

    def test_subset_of(self) -> None:
        assert Range.between(2, 4).subset_of(Range.between(1, 5)) is True
        assert Range.between(0, 4).subset_of(Range.between(1, 5)) is False

    def test_add(self) -> None:
        assert Range.exact(2).add(Range.exact(3)).exact_value == 5

    def test_sub(self) -> None:
        assert Range.exact(5).sub(Range.exact(3)).exact_value == 2

    def test_neg(self) -> None:
        assert Range.exact(5).neg().exact_value == -5

    def test_mul(self) -> None:
        assert Range.exact(2).mul(Range.exact(3)).exact_value == 6

    def test_div(self) -> None:
        res, _may_raise = Range.exact(6).div(Range.exact(2))
        assert res.exact_value == 3

    def test_mod(self) -> None:
        res, _may_raise = Range.exact(7).mod(Range.exact(2))
        assert res.low == 0 and res.high == 1
