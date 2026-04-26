"""Tests for pysymex.utils.math — wilson_upper_95."""

from __future__ import annotations


from pysymex.utils.math import wilson_upper_95


class TestWilsonUpper95:
    """Test suite for the Wilson score upper-95 % confidence bound."""

    def test_zero_trials_returns_zero(self) -> None:
        """wilson_upper_95(k, n=0) must return 0.0 for degenerate input."""
        assert wilson_upper_95(0, 0) == 0.0

    def test_negative_trials_returns_zero(self) -> None:
        """wilson_upper_95(k, n<0) must return 0.0 for negative n."""
        assert wilson_upper_95(5, -1) == 0.0

    def test_all_successes(self) -> None:
        """When k==n, the bound should be close to 1.0 but clamped at 1.0."""
        result = wilson_upper_95(100, 100)
        assert result <= 1.0
        assert result > 0.9

    def test_no_successes(self) -> None:
        """When k==0, the bound should be small but > 0 for small n."""
        result = wilson_upper_95(0, 10)
        assert result > 0.0
        assert result < 0.5

    def test_half_successes(self) -> None:
        """50/100 should produce a bound between 0.5 and 1.0."""
        result = wilson_upper_95(50, 100)
        assert 0.5 < result < 1.0

    def test_clamp_at_one(self) -> None:
        """Result is always <= 1.0 even for extreme k/n."""
        result = wilson_upper_95(1000, 1000)
        assert result <= 1.0

    def test_single_trial_success(self) -> None:
        """1/1 should yield a value < 1.0 due to uncertainty correction."""
        result = wilson_upper_95(1, 1)
        assert 0.0 < result <= 1.0

    def test_large_n_convergence(self) -> None:
        """With large n, the bound should approach p = k/n from above."""
        result = wilson_upper_95(5000, 10000)
        assert 0.5 < result < 0.55
