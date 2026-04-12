from __future__ import annotations

from pysymex.tracing.z3_utils import Z3SemanticRegistry, Z3Serializer


def test_semantic_registry_update_lookup_and_snapshot() -> None:
    registry = Z3SemanticRegistry()
    registry.update({"k!1": "x"})

    assert registry.lookup("k!1") == "x"
    assert registry.lookup("unknown") == "unknown"
    assert registry.snapshot()["k!1"] == "x"


def test_serializer_handles_plain_python_values() -> None:
    serializer = Z3Serializer(Z3SemanticRegistry())

    assert serializer.safe_sexpr({"a": 1}).startswith("{")
    assert serializer.serialize_stack_value(None) == "None"
    ns = serializer.serialize_namespace({"a": 1, "b": [1, 2]})
    assert "a" in ns and "1" in ns["a"]

    entries = serializer.constraints_to_smtlib([1, "x"], causality="test")
    assert len(entries) == 2
    assert entries[0]["causality"] == "test"

