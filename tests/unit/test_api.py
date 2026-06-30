"""Tests for private workflow adapters and their implementation behavior."""

from __future__ import annotations

from pathlib import Path

import pytest

from pysymex._internal.config.coercion import ConfigCoercion
from pysymex._internal.config.values import ConfigValues


class TestToInt:
    """Tests for ConfigCoercion.to_int conversion helper."""

    def test_int_passthrough(self) -> None:
        """Int value is returned as-is."""
        assert ConfigCoercion.to_int(42, 0) == 42

    def test_float_truncated(self) -> None:
        """Float is truncated to int."""
        assert ConfigCoercion.to_int(3.7, 0) == 3

    def test_bool_converted(self) -> None:
        """Bool is converted to 0 or 1."""
        assert ConfigCoercion.to_int(True, 0) == 1
        assert ConfigCoercion.to_int(False, 0) == 0

    def test_valid_string(self) -> None:
        """Numeric string is parsed."""
        assert ConfigCoercion.to_int("123", 0) == 123

    def test_invalid_string_returns_default(self) -> None:
        """Non-numeric string returns default."""
        assert ConfigCoercion.to_int("abc", 99) == 99

    def test_none_returns_default(self) -> None:
        """None returns the default."""
        assert ConfigCoercion.to_int(None, 77) == 77

    def test_list_returns_default(self) -> None:
        """Unsupported type returns default."""
        assert ConfigCoercion.to_int([1, 2], 55) == 55


class TestToFloat:
    """Tests for ConfigCoercion.to_float conversion helper."""

    def test_float_passthrough(self) -> None:
        """Float value is returned as-is."""
        assert ConfigCoercion.to_float(3.14, 0.0) == 3.14

    def test_int_converted(self) -> None:
        """Int is converted to float."""
        assert ConfigCoercion.to_float(5, 0.0) == 5.0

    def test_bool_converted(self) -> None:
        """Bool is converted to 0.0 or 1.0."""
        assert ConfigCoercion.to_float(True, 0.0) == 1.0

    def test_valid_string(self) -> None:
        """Numeric string is parsed."""
        assert ConfigCoercion.to_float("2.5", 0.0) == 2.5

    def test_invalid_string_returns_default(self) -> None:
        """Non-numeric string returns default."""
        assert ConfigCoercion.to_float("abc", 9.9) == 9.9

    def test_none_returns_default(self) -> None:
        """None returns default."""
        assert ConfigCoercion.to_float(None, 1.1) == 1.1


class TestToBool:
    """Tests for ConfigCoercion.to_bool conversion helper."""

    def test_bool_passthrough(self) -> None:
        """Bool returns itself."""
        assert ConfigCoercion.to_bool(True, False) is True
        assert ConfigCoercion.to_bool(False, True) is False

    def test_int_truthy(self) -> None:
        """Non-zero int is truthy."""
        assert ConfigCoercion.to_bool(1, False) is True
        assert ConfigCoercion.to_bool(0, True) is False

    def test_string_true_variants(self) -> None:
        """Various truthy strings are recognized."""
        for s in ("true", "True", "TRUE", "1", "yes", "on"):
            assert ConfigCoercion.to_bool(s, False) is True, f"Failed for {s!r}"

    def test_string_false_variants(self) -> None:
        """Various falsy strings are recognized."""
        for s in ("false", "False", "FALSE", "0", "no", "off"):
            assert ConfigCoercion.to_bool(s, True) is False, f"Failed for {s!r}"

    def test_invalid_string_returns_default(self) -> None:
        """Unrecognized string returns default."""
        assert ConfigCoercion.to_bool("maybe", True) is True

    def test_none_returns_default(self) -> None:
        """None returns default."""
        assert ConfigCoercion.to_bool(None, True) is True


class TestIsObjectMapping:
    """Tests for ConfigValues.is_object_mapping TypeGuard."""

    def test_dict_returns_true(self) -> None:
        """A dict is a Mapping."""
        assert ConfigValues.is_object_mapping({"a": 1}) is True

    def test_list_returns_false(self) -> None:
        """A list is not a Mapping."""
        assert ConfigValues.is_object_mapping([1, 2]) is False

    def test_none_returns_false(self) -> None:
        """None is not a Mapping."""
        assert ConfigValues.is_object_mapping(None) is False


def test_internal_packages_do_not_depend_on_public_workflow_namespaces() -> None:
    """Implementation packages depend inward, not through user workflow facades."""
    allowed_files = {
        Path("pysymex") / "__init__.py",
        Path("pysymex") / "scan.py",
        Path("pysymex") / "verify.py",
    }
    offenders: list[str] = []
    for path in Path("pysymex").rglob("*.py"):
        if path in allowed_files or path.is_relative_to(Path("pysymex") / "_internal" / "cli"):
            continue
        text = path.read_text(encoding="utf-8")
        public_imports = (
            "from pysymex.diagnostics import",
            "from pysymex.reports import",
            "from pysymex.scan import",
            "from pysymex.verify import",
        )
        if any(statement in text for statement in public_imports):
            offenders.append(str(path))

    assert offenders == []


def test_executors_package_does_not_export_config_or_results() -> None:
    """Config and result types live outside the executor package."""
    import pysymex._internal.execution.executors as executors

    for name in ("ExecutionConfig", "ExecutionResult"):
        with pytest.raises(AttributeError):
            getattr(executors, name)
