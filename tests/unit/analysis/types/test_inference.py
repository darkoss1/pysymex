"""Test exports of pysymex.analysis.types.inference."""

import pysymex.analysis.types.inference as i


def test_has_exports() -> None:
    """Test that inference types are exported."""
    exports = [
        "ConfidenceScore",
        "TypeAnalyzer",
        "TypeInferenceEngine",
        "get_type_analyzer",
    ]
    for export in exports:
        assert hasattr(i, export)
