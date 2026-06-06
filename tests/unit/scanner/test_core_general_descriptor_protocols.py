from __future__ import annotations

import asyncio
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pysymex
from pysymex.execution.opcodes.common.functions.attribute.fallbacks import (
    UNSUPPORTED_DESCRIPTOR_PROTOCOL,
)
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


def test_scan_file_data_descriptor_getter_precedes_instance_storage(tmp_path: Path) -> None:
    target = tmp_path / "data_descriptor_getter_precedence.py"
    target.write_text(
        "class Denominator:\n"
        "    def __get__(self, obj, owner) -> int:\n"
        "        return 0\n\n"
        "    def __set__(self, obj, value: int) -> None:\n"
        "        pass\n\n"
        "class Record:\n"
        "    denominator = Denominator()\n\n"
        "    def __init__(self) -> None:\n"
        "        self.denominator = 1\n\n"
        "def target() -> int:\n"
        "    return 10 // Record().denominator\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_data_descriptor_precedes_instance_dict_shadowing(tmp_path: Path) -> None:
    target = tmp_path / "data_descriptor_instance_dict_shadow.py"
    target.write_text(
        "class Descriptor:\n"
        "    def __get__(self, instance, owner):\n"
        "        return 3\n\n"
        "    def __set__(self, instance, value):\n"
        "        instance.stored = value\n\n"
        "class Owner:\n"
        "    value = Descriptor()\n\n"
        "def target() -> int:\n"
        "    item = Owner()\n"
        "    item.__dict__['value'] = 5\n"
        "    return item.value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    _assert_no_issue_kinds(result, {"ATTRIBUTE_ERROR", "TYPE_ERROR"})


def test_analyze_code_data_descriptor_precedes_instance_dict_shadowing() -> None:
    result = asyncio.run(
        pysymex.analyze_code(
            "class Descriptor:\n"
            "    def __get__(self, instance, owner):\n"
            "        return 3\n"
            "    def __set__(self, instance, value):\n"
            "        instance.stored = value\n"
            "class Owner:\n"
            "    value = Descriptor()\n\n"
            "item = Owner()\n"
            "item.__dict__['value'] = 5\n"
            "result = item.value\n",
            max_paths=35,
            max_depth=100,
            max_iterations=2200,
            timeout=2.0,
        )
    )

    _assert_no_issue_kinds(result, {"ATTRIBUTE_ERROR", "TYPE_ERROR", "NAME_ERROR"})


def test_scan_file_non_data_descriptor_yields_to_instance_storage(tmp_path: Path) -> None:
    target = tmp_path / "non_data_descriptor_shadowing.py"
    target.write_text(
        "class Denominator:\n"
        "    def __get__(self, obj, owner) -> int:\n"
        "        return 0\n\n"
        "class Record:\n"
        "    denominator = Denominator()\n\n"
        "    def __init__(self) -> None:\n"
        "        self.denominator = 1\n\n"
        "def target() -> int:\n"
        "    return 10 // Record().denominator\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_data_descriptor_setter(tmp_path: Path) -> None:
    target = tmp_path / "data_descriptor_setter.py"
    target.write_text(
        "class Value:\n"
        "    def __get__(self, obj, owner) -> int:\n"
        "        return 1\n\n"
        "    def __set__(self, obj, value: int) -> None:\n"
        "        10 // value\n\n"
        "class Record:\n"
        "    value = Value()\n\n"
        "def target(value: int) -> None:\n"
        "    Record().value = value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_data_descriptor_deleter(tmp_path: Path) -> None:
    target = tmp_path / "data_descriptor_deleter.py"
    target.write_text(
        "class Value:\n"
        "    def __delete__(self, obj) -> None:\n"
        "        10 // 0\n\n"
        "class Record:\n"
        "    value = Value()\n\n"
        "def target() -> None:\n"
        "    del Record().value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_degrades_descriptor_that_requires_constructor_state(tmp_path: Path) -> None:
    target = tmp_path / "stateful_descriptor.py"
    target.write_text(
        "class Value:\n"
        "    def __init__(self) -> None:\n"
        "        self.result = 1\n\n"
        "    def __get__(self, obj, owner) -> int:\n"
        "        return self.result\n\n"
        "class Record:\n"
        "    value = Value()\n\n"
        "def target() -> int:\n"
        "    return 10 // Record().value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_literal_descriptor_constructor_state(tmp_path: Path) -> None:
    target = tmp_path / "descriptor_constructor_arguments.py"
    target.write_text(
        "class Value:\n"
        "    def __init__(self, result: int) -> None:\n"
        "        self.result = result\n\n"
        "    def __get__(self, obj, owner) -> int:\n"
        "        return self.result\n\n"
        "class Record:\n"
        "    value = Value(0)\n\n"
        "def target() -> int:\n"
        "    return 10 // Record().value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert not any(issue.get("kind") == "ATTRIBUTE_ERROR" for issue in result.issues)


def test_scan_file_executes_descriptor_getter_through_getattr_builtin(tmp_path: Path) -> None:
    target = tmp_path / "descriptor_builtin_getattr.py"
    target.write_text(
        "class Value:\n"
        "    def __get__(self, obj, owner) -> int:\n"
        "        return 0\n\n"
        "class Record:\n"
        "    value = Value()\n\n"
        "def target() -> int:\n"
        "    return 10 // getattr(Record(), 'value')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_nested_descriptor_getter_without_attribute_error(
    tmp_path: Path,
) -> None:
    target = tmp_path / "nested_descriptor_getter.py"
    target.write_text(
        "def target() -> int:\n"
        "    class Descriptor:\n"
        "        def __get__(self, instance: object, owner: object) -> int:\n"
        "            return 3\n\n"
        "    class Owner:\n"
        "        value = Descriptor()\n\n"
        "    return Owner().value + 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    _assert_no_issue_kinds(result, {"ATTRIBUTE_ERROR", "TYPE_ERROR"})


def test_scan_file_executes_nested_descriptor_setter_without_attribute_error(
    tmp_path: Path,
) -> None:
    target = tmp_path / "nested_descriptor_setter.py"
    target.write_text(
        "def target() -> int:\n"
        "    class Descriptor:\n"
        "        def __set__(self, instance: object, value: int) -> None:\n"
        "            instance.stored = value\n\n"
        "    class Owner:\n"
        "        value = Descriptor()\n\n"
        "    owner = Owner()\n"
        "    owner.value = 5\n"
        "    return owner.stored\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    _assert_no_issue_kinds(result, {"ATTRIBUTE_ERROR", "TYPE_ERROR"})


def test_analyze_code_executes_descriptor_getter_without_static_prebinding() -> None:
    result = asyncio.run(
        pysymex.analyze_code(
            "class Descriptor:\n"
            "    def __get__(self, instance: object, owner: object) -> int:\n"
            "        return 3\n"
            "class Owner:\n"
            "    value = Descriptor()\n\n"
            "result = Owner().value + 1\n",
            max_paths=30,
            max_depth=80,
            max_iterations=1500,
            timeout=2.0,
        )
    )

    _assert_no_issue_kinds(result, {"ATTRIBUTE_ERROR", "TYPE_ERROR", "NAME_ERROR"})


def test_scan_file_getattr_builtin_data_descriptor_precedes_instance_storage(
    tmp_path: Path,
) -> None:
    target = tmp_path / "descriptor_builtin_data_precedence.py"
    target.write_text(
        "class Value:\n"
        "    def __get__(self, obj, owner) -> int:\n"
        "        return 0\n\n"
        "    def __set__(self, obj, value: int) -> None:\n"
        "        pass\n\n"
        "class Record:\n"
        "    value = Value()\n\n"
        "    def __init__(self) -> None:\n"
        "        self.value = 1\n\n"
        "def target() -> int:\n"
        "    return 10 // getattr(Record(), 'value')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_getattr_builtin_non_data_descriptor_yields_to_instance_storage(
    tmp_path: Path,
) -> None:
    target = tmp_path / "descriptor_builtin_non_data_shadowing.py"
    target.write_text(
        "class Value:\n"
        "    def __get__(self, obj, owner) -> int:\n"
        "        return 0\n\n"
        "class Record:\n"
        "    value = Value()\n\n"
        "    def __init__(self) -> None:\n"
        "        self.value = 1\n\n"
        "def target() -> int:\n"
        "    return 10 // getattr(Record(), 'value')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_descriptor_getattr_error_runs_getattr_before_default(tmp_path: Path) -> None:
    target = tmp_path / "descriptor_builtin_default_chain.py"
    target.write_text(
        "class Value:\n"
        "    def __get__(self, obj, owner) -> int:\n"
        "        raise AttributeError('value')\n\n"
        "class Record:\n"
        "    value = Value()\n\n"
        "    def __getattr__(self, name: str) -> int:\n"
        "        return 1\n\n"
        "def target() -> int:\n"
        "    return 10 // getattr(Record(), 'value', 0)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_descriptor_getattr_error_uses_default(tmp_path: Path) -> None:
    target = tmp_path / "descriptor_builtin_default.py"
    target.write_text(
        "class Value:\n"
        "    def __get__(self, obj, owner) -> int:\n"
        "        raise AttributeError('value')\n\n"
        "class Record:\n"
        "    value = Value()\n\n"
        "def target() -> int:\n"
        "    return 10 // getattr(Record(), 'value', 0)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_descriptor_setter_through_setattr_builtin(tmp_path: Path) -> None:
    target = tmp_path / "descriptor_builtin_setattr.py"
    target.write_text(
        "class Value:\n"
        "    def __set__(self, obj, value: int) -> None:\n"
        "        10 // value\n\n"
        "class Record:\n"
        "    value = Value()\n\n"
        "def target(value: int) -> None:\n"
        "    setattr(Record(), 'value', value)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_descriptor_deleter_through_delattr_builtin(tmp_path: Path) -> None:
    target = tmp_path / "descriptor_builtin_delattr.py"
    target.write_text(
        "class Value:\n"
        "    def __delete__(self, obj) -> None:\n"
        "        10 // 0\n\n"
        "class Record:\n"
        "    value = Value()\n\n"
        "def target() -> None:\n"
        "    delattr(Record(), 'value')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_degrades_stateful_descriptor_through_getattr_builtin(tmp_path: Path) -> None:
    target = tmp_path / "descriptor_builtin_stateful.py"
    target.write_text(
        "class Value:\n"
        "    def __init__(self) -> None:\n"
        "        self.result = 1\n\n"
        "    def __get__(self, obj, owner) -> int:\n"
        "        return self.result\n\n"
        "class Record:\n"
        "    value = Value()\n\n"
        "def target() -> int:\n"
        "    return 10 // getattr(Record(), 'value')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_suppresses_range_warning_after_descriptor_degradation(
    tmp_path: Path,
) -> None:
    target = tmp_path / "descriptor_degraded_range_warning.py"
    target.write_text(
        "class Value:\n"
        "    def __init__(self) -> None:\n"
        "        self.result = 0\n\n"
        "    def __get__(self, obj, owner) -> int:\n"
        "        return self.result\n\n"
        "class Record:\n"
        "    value = Value()\n\n"
        "def target() -> int:\n"
        "    value = Record().value\n"
        "    denom = 0\n"
        "    if value:\n"
        "        return 1 // denom\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert UNSUPPORTED_DESCRIPTOR_PROTOCOL in result.degraded_passes
    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and str(issue.get("message", "")).startswith("[Value Range]")
        for issue in result.issues
    )
