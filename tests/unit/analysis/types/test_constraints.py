"""Test exports of pysymex.analysis.types.constraints."""

import pysymex.analysis.types.constraints as c


def test_has_exports() -> None:
    """Test that all expected exports are present."""
    exports = [
        "Protocol",
        "ProtocolChecker",
        "SymbolicType",
        "TypeConstraintChecker",
        "TypeIssue",
        "TypeIssueKind",
        "TypeKind",
        "Variance",
    ]
    for export in exports:
        assert hasattr(c, export)
