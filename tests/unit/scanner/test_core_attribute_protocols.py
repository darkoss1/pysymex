from __future__ import annotations

from pathlib import Path

from pysymex.execution.opcodes.common.functions.attribute.fallbacks import (
    UNSUPPORTED_ATTRIBUTE_PROTOCOL,
)
from pysymex.scanner.file import scan_file


def test_scan_file_executes_safe_custom_getattr_result(tmp_path: Path) -> None:
    target = tmp_path / "custom_getattr_safe.py"
    target.write_text(
        "class Data:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __getattr__(self, name: str) -> int:\n"
        "        if name == 'denominator':\n"
        "            return 1 if self.value == 0 else self.value\n"
        "        return 1\n\n"
        "def target(value: int) -> int:\n"
        "    return 10 // Data(value).denominator\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_preserves_custom_getattr_bug_result(tmp_path: Path) -> None:
    target = tmp_path / "custom_getattr_bug.py"
    target.write_text(
        "class Data:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __getattr__(self, name: str) -> int:\n"
        "        return self.value\n\n"
        "def target(value: int) -> int:\n"
        "    return 10 // Data(value).denominator\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_custom_getattribute_on_missing_attribute(tmp_path: Path) -> None:
    target = tmp_path / "custom_getattribute_missing.py"
    target.write_text(
        "class Data:\n"
        "    def __getattribute__(self, name: str) -> int:\n"
        "        return 1\n\n"
        "def target() -> int:\n"
        "    return Data().missing\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_attribute_protocol" not in result.degraded_passes


def test_scan_file_custom_getattribute_precedes_stored_attribute(tmp_path: Path) -> None:
    target = tmp_path / "custom_getattribute_existing_bug.py"
    target.write_text(
        "class Data:\n"
        "    def __init__(self) -> None:\n"
        "        self.denominator = 1\n\n"
        "    def __getattribute__(self, name: str) -> int:\n"
        "        return 0\n\n"
        "def target() -> int:\n"
        "    return 10 // Data().denominator\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_safe_custom_getattr_through_builtin(tmp_path: Path) -> None:
    target = tmp_path / "builtin_custom_getattr_safe.py"
    target.write_text(
        "class Data:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __getattr__(self, name: str) -> int:\n"
        "        return 1 if self.value == 0 else self.value\n\n"
        "def target(value: int) -> int:\n"
        "    return 10 // getattr(Data(value), 'denominator')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_preserves_custom_getattr_bug_through_builtin(tmp_path: Path) -> None:
    target = tmp_path / "builtin_custom_getattr_bug.py"
    target.write_text(
        "class Data:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __getattr__(self, name: str) -> int:\n"
        "        return self.value\n\n"
        "def target(value: int) -> int:\n"
        "    return 10 // getattr(Data(value), 'denominator')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_custom_getattribute_precedes_stored_attribute_through_builtin(
    tmp_path: Path,
) -> None:
    target = tmp_path / "builtin_custom_getattribute_existing_bug.py"
    target.write_text(
        "class Data:\n"
        "    def __init__(self) -> None:\n"
        "        self.denominator = 1\n\n"
        "    def __getattribute__(self, name: str) -> int:\n"
        "        return 0\n\n"
        "def target() -> int:\n"
        "    return 10 // getattr(Data(), 'denominator')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_getattr_default_with_successful_custom_hook(tmp_path: Path) -> None:
    target = tmp_path / "builtin_custom_getattr_default_success.py"
    target.write_text(
        "class Data:\n"
        "    def __getattr__(self, name: str) -> int:\n"
        "        return 1\n\n"
        "def target() -> int:\n"
        "    return 10 // getattr(Data(), 'missing', 0)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_attribute_protocol" not in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_getattr_default_with_successful_custom_getattribute(
    tmp_path: Path,
) -> None:
    target = tmp_path / "builtin_custom_getattribute_default_success.py"
    target.write_text(
        "class Data:\n"
        "    def __getattribute__(self, name: str) -> int:\n"
        "        return 1\n\n"
        "def target() -> int:\n"
        "    return 10 // getattr(Data(), 'missing', 0)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_attribute_protocol" not in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_uses_getattr_default_after_custom_getattr_attribute_error(
    tmp_path: Path,
) -> None:
    target = tmp_path / "builtin_custom_getattr_default_error.py"
    target.write_text(
        "class Data:\n"
        "    def __getattr__(self, name: str) -> int:\n"
        "        raise AttributeError(name)\n\n"
        "def target() -> int:\n"
        "    return 10 // getattr(Data(), 'missing', 0)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_attribute_protocol" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_uses_getattr_default_after_getattribute_attribute_error(
    tmp_path: Path,
) -> None:
    target = tmp_path / "builtin_custom_getattribute_default_error.py"
    target.write_text(
        "class Data:\n"
        "    def __getattribute__(self, name: str) -> int:\n"
        "        raise AttributeError(name)\n\n"
        "def target() -> int:\n"
        "    return 10 // getattr(Data(), 'missing', 0)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_attribute_protocol" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_getattr_default_primary_to_getattr_chaining(
    tmp_path: Path,
) -> None:
    target = tmp_path / "builtin_custom_getattribute_getattr_default_success.py"
    target.write_text(
        "class Data:\n"
        "    def __getattribute__(self, name: str) -> int:\n"
        "        raise AttributeError(name)\n\n"
        "    def __getattr__(self, name: str) -> int:\n"
        "        return 1\n\n"
        "def target() -> int:\n"
        "    return 10 // getattr(Data(), 'missing', 0)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_attribute_protocol" not in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_uses_default_after_both_custom_lookup_hooks_raise(
    tmp_path: Path,
) -> None:
    target = tmp_path / "builtin_custom_lookup_chain_default_error.py"
    target.write_text(
        "class Data:\n"
        "    def __getattribute__(self, name: str) -> int:\n"
        "        raise AttributeError(name)\n\n"
        "    def __getattr__(self, name: str) -> int:\n"
        "        raise AttributeError(name)\n\n"
        "def target() -> int:\n"
        "    return 10 // getattr(Data(), 'missing', 0)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_attribute_protocol" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_suppresses_range_warning_after_attribute_degradation(
    tmp_path: Path,
) -> None:
    target = tmp_path / "attribute_degraded_range_warning.py"
    target.write_text(
        "class Data:\n"
        "    def __getattr__(self, name: str) -> int:\n"
        "        return self.missing\n\n"
        "def target() -> int:\n"
        "    value = Data().value\n"
        "    denom = 0\n"
        "    if value:\n"
        "        return 1 // denom\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert UNSUPPORTED_ATTRIBUTE_PROTOCOL in result.degraded_passes
    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and str(issue.get("message", "")).startswith("[Value Range]")
        for issue in result.issues
    )


def test_scan_file_property_getter_preserves_closure_parameter_type(tmp_path: Path) -> None:
    target = tmp_path / "property_getter_closure.py"
    target.write_text(
        "def target(y: int) -> int:\n"
        "    class Box:\n"
        "        @property\n"
        "        def value(self) -> int:\n"
        "            return 10 // y\n"
        "    box = Box()\n"
        "    return box.value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)
    issue_kinds = {issue.get("kind") for issue in result.issues}

    assert "DIVISION_BY_ZERO" in issue_kinds
    assert "TYPE_ERROR" not in issue_kinds


def test_scan_file_class_method_preserves_closure_parameter_type(tmp_path: Path) -> None:
    target = tmp_path / "class_method_closure.py"
    target.write_text(
        "def target(y: int) -> int:\n"
        "    class Box:\n"
        "        def value(self) -> int:\n"
        "            return 10 // y\n"
        "    return Box().value()\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)
    issue_kinds = {issue.get("kind") for issue in result.issues}

    assert "DIVISION_BY_ZERO" in issue_kinds
    assert "TYPE_ERROR" not in issue_kinds
