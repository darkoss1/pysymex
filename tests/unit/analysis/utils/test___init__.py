"""Test exports of pysymex.analysis.utils.__init__."""

import pysymex.analysis.utils as u


def test_has_exports() -> None:
    """Test that util types are exported."""
    assert hasattr(u, "wilson_upper_95")
