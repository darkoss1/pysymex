"""Test exports of pysymex.analysis.types.stubs."""

import pysymex.analysis.types.stubs as s


def test_has_exports() -> None:
    """Test that stub types are exported."""
    exports = [
        "BuiltinStubs",
        "ClassStub",
        "FunctionStub",
        "ModuleStub",
        "StubBasedTypeResolver",
        "StubParser",
        "StubRepository",
        "StubType",
    ]
    for export in exports:
        assert hasattr(s, export)
