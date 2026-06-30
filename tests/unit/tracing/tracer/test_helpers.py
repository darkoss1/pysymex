"""Tests for pysymex._internal.tracing.tracer.serialization — config snapshots and scalars."""

from __future__ import annotations

import json
from typing import Any

from pysymex._internal.tracing.tracer.serialization import TraceSerialization


class TestToConfigScalar:
    """Tests for TraceSerialization.scalar coercion."""

    def test_none_passthrough(self) -> None:
        """None passes through."""
        assert TraceSerialization.scalar(None) is None

    def test_str_passthrough(self) -> None:
        """String passes through."""
        assert TraceSerialization.scalar("hello") == "hello"

    def test_int_passthrough(self) -> None:
        """Int passes through."""
        assert TraceSerialization.scalar(42) == 42

    def test_float_passthrough(self) -> None:
        """Float passes through."""
        assert TraceSerialization.scalar(3.14) == 3.14

    def test_bool_passthrough(self) -> None:
        """Bool passes through."""
        assert TraceSerialization.scalar(True) is True

    def test_bytes_decoded(self) -> None:
        """Bytes are decoded to string."""
        result: Any = TraceSerialization.scalar(b"hello")
        assert result == "hello"

    def test_dict_serialized(self) -> None:
        """Dict is JSON-serialized."""
        result: Any = TraceSerialization.scalar({"key": "value"})
        assert isinstance(result, str)
        parsed = json.loads(result)
        assert parsed["key"] == "value"

    def test_list_serialized(self) -> None:
        """List is JSON-serialized."""
        result: Any = TraceSerialization.scalar([1, 2, 3])
        assert isinstance(result, str)
        parsed = json.loads(result)
        assert parsed == [1, 2, 3]


class TestNormaliseConfigSnapshot:
    """Tests for TraceSerialization.config_snapshot."""

    def test_scalar_values(self) -> None:
        """Scalar values pass through."""
        snapshot: dict[str, object] = {"timeout": 5000, "name": "test"}
        result: Any = TraceSerialization.config_snapshot(snapshot)
        assert result["timeout"] == 5000
        assert result["name"] == "test"

    def test_complex_values(self) -> None:
        """Complex values are serialized."""
        snapshot: dict[str, object] = {"nested": {"a": 1}}
        result: Any = TraceSerialization.config_snapshot(snapshot)
        assert isinstance(result["nested"], str)

    def test_empty_snapshot(self) -> None:
        """Empty dict produces empty result."""
        result: Any = TraceSerialization.config_snapshot({})
        assert result == {}
