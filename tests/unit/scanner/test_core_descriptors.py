"""Tests for scanner descriptor and slot attribute semantics."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_reports_forbidden_slotted_attribute_store(tmp_path: Path) -> None:
    """Writes outside literal __slots__ should be reported as AttributeError."""
    target = tmp_path / "slotted_forbidden_store.py"
    target.write_text(
        "class Slotted:\n"
        "    __slots__ = ('ready',)\n\n"
        "def target() -> int:\n"
        "    obj = Slotted()\n"
        "    obj.extra = 1\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "ATTRIBUTE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 6
        for issue in result.issues
    )


def test_scan_file_allows_declared_slotted_attribute_store(tmp_path: Path) -> None:
    """Declared slots should allow writes and later reads."""
    target = tmp_path / "slotted_allowed_store.py"
    target.write_text(
        "class Slotted:\n"
        "    __slots__ = ('ready',)\n\n"
        "def target() -> int:\n"
        "    obj = Slotted()\n"
        "    obj.ready = 1\n"
        "    return obj.ready\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "ATTRIBUTE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") in {6, 7}
        for issue in result.issues
    )


def test_scan_file_reports_readonly_property_store(tmp_path: Path) -> None:
    """Read-only property descriptors should reject STORE_ATTR."""
    target = tmp_path / "readonly_property_store.py"
    target.write_text(
        "class Record:\n"
        "    @property\n"
        "    def value(self) -> int:\n"
        "        return 4\n\n"
        "def target() -> int:\n"
        "    obj = Record()\n"
        "    obj.value = 3\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "ATTRIBUTE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 8
        for issue in result.issues
    )


def test_scan_file_reports_local_readonly_property_store(tmp_path: Path) -> None:
    """Local classes should keep property descriptors through __build_class__."""
    target = tmp_path / "local_readonly_property_store.py"
    target.write_text(
        "def target() -> int:\n"
        "    class Record:\n"
        "        @property\n"
        "        def value(self) -> int:\n"
        "            return 4\n"
        "    obj = Record()\n"
        "    obj.value = 3\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "ATTRIBUTE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 7
        for issue in result.issues
    )


def test_scan_file_allows_settable_property_store(tmp_path: Path) -> None:
    """Property setters should prevent read-only property false positives."""
    target = tmp_path / "settable_property_store.py"
    target.write_text(
        "class Record:\n"
        "    def __init__(self) -> None:\n"
        "        self.value = 1\n\n"
        "    @property\n"
        "    def value(self) -> int:\n"
        "        return self.value\n\n"
        "    @value.setter\n"
        "    def value(self, new_value: int) -> None:\n"
        "        self.value = new_value\n\n"
        "def target() -> int:\n"
        "    obj = Record()\n"
        "    obj.value = 3\n"
        "    return obj.value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "ATTRIBUTE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") in {15, 16}
        for issue in result.issues
    )


def test_scan_file_respects_custom_bool_guard_against_zero_division(tmp_path: Path) -> None:
    """A user ``__bool__`` guard should constrain guarded arithmetic."""
    target = tmp_path / "custom_bool_safe_guard.py"
    target.write_text(
        "class Box:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __bool__(self) -> bool:\n"
        "        return self.value != 0\n\n"
        "def target(value: int) -> int:\n"
        "    box = Box(value)\n"
        "    if box:\n"
        "        return 1 // value\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 11
        for issue in result.issues
    )


def test_scan_file_respects_custom_bool_negated_bug_path(tmp_path: Path) -> None:
    """The false result of ``__bool__`` must keep real bug paths reachable."""
    target = tmp_path / "custom_bool_negated_bug.py"
    target.write_text(
        "class Box:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __bool__(self) -> bool:\n"
        "        return self.value != 0\n\n"
        "def target(value: int) -> int:\n"
        "    box = Box(value)\n"
        "    if not box:\n"
        "        return 1 // value\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 11
        for issue in result.issues
    )


def test_scan_file_respects_custom_bool_in_boolean_chain(tmp_path: Path) -> None:
    """Truth-protocol execution should also apply inside chained guards."""
    target = tmp_path / "custom_bool_boolean_chain.py"
    target.write_text(
        "class Box:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __bool__(self) -> bool:\n"
        "        return self.value != 0\n\n"
        "def target(value: int) -> int:\n"
        "    box = Box(value)\n"
        "    if box and value > -10:\n"
        "        return 1 // value\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 11
        for issue in result.issues
    )


def test_scan_file_respects_custom_bool_through_builtin_bool(tmp_path: Path) -> None:
    """Explicit ``bool(instance)`` should use the modeled truth protocol."""
    target = tmp_path / "custom_bool_explicit_call.py"
    target.write_text(
        "class Box:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __bool__(self) -> bool:\n"
        "        return self.value != 0\n\n"
        "def target(value: int) -> int:\n"
        "    box = Box(value)\n"
        "    if bool(box):\n"
        "        return 1 // value\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 11
        for issue in result.issues
    )


def test_scan_file_reports_invalid_custom_bool_return_type(tmp_path: Path) -> None:
    """CPython rejects a definite non-bool return from ``__bool__``."""
    target = tmp_path / "custom_bool_invalid_return.py"
    target.write_text(
        "class Box:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __bool__(self) -> bool:\n"
        "        return self.value + 1\n\n"
        "def target(value: int) -> int:\n"
        "    box = Box(value)\n"
        "    if box:\n"
        "        return 1\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and "__bool__ should return bool" in str(issue.get("message"))
        for issue in result.issues
    )
