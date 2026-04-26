"""Tests for pysymex.analysis.utils.math."""

from pysymex.analysis.utils.math import wilson_upper_95


def test_wilson_upper_95_zero_n() -> None:
    """Test wilson_upper_95 returns 0.0 when n is 0."""
    result = wilson_upper_95(5, 0)
    assert result == 0.0


def test_wilson_upper_95_negative_n() -> None:
    """Test wilson_upper_95 returns 0.0 when n is negative."""
    result = wilson_upper_95(5, -1)
    assert result == 0.0


def test_wilson_upper_95_normal() -> None:
    """Test wilson_upper_95 calculates correctly for normal values."""
    result = wilson_upper_95(50, 100)
    assert result > 0.5
    assert result < 0.65


def test_wilson_upper_95_max_bound() -> None:
    """Test wilson_upper_95 is bounded by 1.0 when k=n is small."""
    result = wilson_upper_95(1, 1)
    assert result == 1.0
