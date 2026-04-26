"""Test exports of pysymex.analysis.types.patterns."""

import pysymex.analysis.types.patterns as p


def test_has_exports() -> None:
    """Test that pattern types are exported."""
    exports = ["PatternRecognizer", "TypeState", "TypeStateMachine"]
    for export in exports:
        assert hasattr(p, export)
