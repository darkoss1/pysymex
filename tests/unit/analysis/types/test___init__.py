"""Test exports of pysymex.analysis.types.__init__."""

from typing import Any
import pysymex.analysis.types as t


def test_has_exports() -> None:
    """Test that all expected exports are present."""
    exports = [
        "ConfidenceScore",
        "BuiltinStubs",
        "ClassStub",
        "FunctionStub",
        "ModuleStub",
        "PatternRecognizer",
        "Protocol",
        "ProtocolChecker",
        "PyType",
        "SymbolicType",
        "StubBasedTypeResolver",
        "StubParser",
        "StubRepository",
        "StubType",
        "TypeAnalyzer",
        "TypeConstraintChecker",
        "TypeEnvironment",
        "TypeInferenceEngine",
        "TypeIssue",
        "TypeIssueKind",
        "TypeKind",
        "TypeState",
        "TypeStateMachine",
        "Variance",
        "get_type_analyzer",
    ]
    for export in exports:
        assert hasattr(t, export)
