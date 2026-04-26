"""Test exports of pysymex.analysis.contracts.compiler."""

import pysymex.analysis.contracts.compiler as c


def test_has_exports() -> None:
    """Test that ContractCompiler is exported."""
    assert hasattr(c, "ContractCompiler")
