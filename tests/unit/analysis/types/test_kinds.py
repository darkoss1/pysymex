"""Test exports of pysymex.analysis.types.kinds."""

import pysymex.analysis.types.kinds as k


def test_has_exports() -> None:
    """Test that type kinds are exported."""
    exports = ["PyType", "TypeKind"]
    for export in exports:
        assert hasattr(k, export)
