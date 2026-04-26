"""Test exports of pysymex.analysis.types.environment."""

import pysymex.analysis.types.environment as e


def test_has_exports() -> None:
    """Test that TypeEnvironment is exported."""
    assert hasattr(e, "TypeEnvironment")
