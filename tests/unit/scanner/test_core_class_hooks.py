"""Tests for bounded class-variable and abstract-class scanner behavior."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pysymex
from pysymex.scanner.file import scan_file


def _assert_no_issue_kinds(result: object, forbidden: set[str]) -> None:
    issues = getattr(result, "issues", [])
    assert not any(_issue_kind(issue) in forbidden for issue in issues)


def _issue_kind(issue: object) -> object:
    if isinstance(issue, dict):
        issue_map = cast("Mapping[str, object]", issue)
        return issue_map.get("kind")
    raw_kind = getattr(issue, "kind", None)
    return getattr(raw_kind, "name", raw_kind)


def test_scan_file_preserves_literal_class_zero_without_type_noise(tmp_path: Path) -> None:
    """Literal integer class attributes keep the concrete zero bug type."""
    target = tmp_path / "literal_class_zero.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    class Counter:\n"
        "        count = 0\n"
        "    return x // Counter.count\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 4
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 4
        for issue in result.issues
    )


def test_scan_file_rejects_abstract_class_instantiation(tmp_path: Path) -> None:
    """A directly instantiated source-visible abstract class must report TypeError."""
    target = tmp_path / "abstract_instantiation.py"
    target.write_text(
        "from abc import ABC, abstractmethod\n\n"
        "class AbstractOnly(ABC):\n"
        "    @abstractmethod\n"
        "    def run(self) -> bool: ...\n"
        "def target() -> object:\n"
        "    return AbstractOnly()\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 7
        and "Can't instantiate abstract class AbstractOnly" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_allows_implemented_abstract_override(tmp_path: Path) -> None:
    """A subclass implementation resolves inherited abstract requirements."""
    target = tmp_path / "implemented_abstract_override.py"
    target.write_text(
        "from abc import ABC, abstractmethod\n\n"
        "class OverrideBase(ABC):\n"
        "    @abstractmethod\n"
        "    def validate(self, value: int) -> bool: ...\n\n"
        "class ConcreteOverride(OverrideBase):\n"
        "    def validate(self, value: int) -> bool:\n"
        "        return True\n\n"
        "def target() -> object:\n"
        "    return ConcreteOverride()\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "TYPE_ERROR"
        and "Can't instantiate abstract class ConcreteOverride" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_models_bounded_init_subclass_registry(tmp_path: Path) -> None:
    """A canonical subclass registry exposes concrete declared class values."""
    target = tmp_path / "bounded_subclass_registry.py"
    target.write_text(
        "class Registry:\n"
        "    _subclasses: list = []\n\n"
        "    def __init_subclass__(cls, tag: str = '', **kwargs):\n"
        "        super().__init_subclass__(**kwargs)\n"
        "        Registry._subclasses.append((tag, cls))\n\n"
        "class Good(Registry, tag='good'):\n"
        "    value = 1\n\n"
        "class Bad(Registry, tag='bad'):\n"
        "    value = 0\n\n"
        "def target() -> int:\n"
        "    total = 0\n"
        "    for tag, cls in Registry._subclasses:\n"
        "        total += 10 // cls.value\n"
        "    return total\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 17
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") in {"TYPE_ERROR", "NULL_DEREFERENCE"}
        and issue.get("function_name") == "target"
        and issue.get("line") == 17
        for issue in result.issues
    )


def test_scan_file_class_decorator_attribute_write_updates_class(tmp_path: Path) -> None:
    """A class decorator mutating ``cls`` must update modeled class attributes."""
    target = tmp_path / "class_decorator_attr.py"
    target.write_text(
        "def target() -> int:\n"
        "    def decorate(cls):\n"
        "        cls.value = 3\n"
        "        return cls\n\n"
        "    @decorate\n"
        "    class Box:\n"
        "        pass\n\n"
        "    result = Box.value\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    _assert_no_issue_kinds(result, {"ATTRIBUTE_ERROR", "TYPE_ERROR", "NAME_ERROR"})


def test_analyze_code_class_decorator_attribute_write_updates_class() -> None:
    """Direct module analysis keeps decorator class-attribute writes visible."""
    result = asyncio.run(
        pysymex.analyze_code(
            "def decorate(cls):\n"
            "    cls.value = 3\n"
            "    return cls\n\n"
            "@decorate\n"
            "class Box:\n"
            "    pass\n\n"
            "result = Box.value\n",
            max_paths=20,
            max_depth=80,
            max_iterations=1500,
            timeout=2.0,
        )
    )

    _assert_no_issue_kinds(result, {"ATTRIBUTE_ERROR", "TYPE_ERROR", "NAME_ERROR"})


def test_analyze_code_metaclass_call_initializes_instance_attribute() -> None:
    """A custom metaclass ``__call__`` can initialize attributes before returning."""
    result = asyncio.run(
        pysymex.analyze_code(
            "class Meta(type):\n"
            "    def __call__(cls, value: int = 2):\n"
            "        item = super().__call__()\n"
            "        item.value = value + 1\n"
            "        return item\n"
            "class Box(metaclass=Meta):\n"
            "    pass\n\n"
            "result = Box().value\n",
            max_paths=35,
            max_depth=100,
            max_iterations=2200,
            timeout=2.0,
        )
    )

    _assert_no_issue_kinds(
        result,
        {"ATTRIBUTE_ERROR", "TYPE_ERROR", "NAME_ERROR", "UNBOUND_VARIABLE", "UNHANDLED_EXCEPTION"},
    )
    assert "unsupported_super_protocol" not in result.degraded_passes
    assert "unsupported_construction_protocol" not in result.degraded_passes


def test_scan_file_metaclass_call_initializes_instance_attribute(tmp_path: Path) -> None:
    """Scanner keeps metaclass ``__call__`` instance writes visible after construction."""
    target = tmp_path / "metaclass_call_attribute.py"
    target.write_text(
        "def target() -> int:\n"
        "    class Meta(type):\n"
        "        def __call__(cls, value: int = 2):\n"
        "            item = super().__call__()\n"
        "            item.value = value + 1\n"
        "            return item\n"
        "    class Box(metaclass=Meta):\n"
        "        pass\n\n"
        "    result = Box().value\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind")
        in {
            "ATTRIBUTE_ERROR",
            "TYPE_ERROR",
            "NAME_ERROR",
            "UNBOUND_VARIABLE",
            "UNHANDLED_EXCEPTION",
        }
        and issue.get("function_name") == "target"
        for issue in result.issues
    )
    assert "unsupported_super_protocol" not in result.degraded_passes
    assert "unsupported_construction_protocol" not in result.degraded_passes


def test_scan_file_reaches_zero_through_concrete_abstract_override(tmp_path: Path) -> None:
    """A concrete override called through a bounded loop preserves the zero path."""
    target = tmp_path / "abstract_override_division.py"
    target.write_text(
        "from abc import ABC, abstractmethod\n"
        "class LoopBase(ABC):\n"
        "    @abstractmethod\n"
        "    def validate(self, value: int) -> bool: ...\n"
        "    def accept(self, value: int) -> int:\n"
        "        if not self.validate(value):\n"
        "            raise ValueError('invalid')\n"
        "        return value\n"
        "class LoopChild(LoopBase):\n"
        "    def __init__(self, low: int, high: int):\n"
        "        self.low = low\n"
        "        self.high = high\n"
        "    def validate(self, value: int) -> bool:\n"
        "        return self.low <= value <= self.high\n"
        "def target():\n"
        "    v = LoopChild(0, 10)\n"
        "    for val in range(11):\n"
        "        safe = v.accept(val)\n"
        "        out = 1 // safe\n"
        "    return out\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 19
        for issue in result.issues
    )
