from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_executes_safe_readonly_property_getter(tmp_path: Path) -> None:
    target = tmp_path / "readonly_property_getter_safe.py"
    target.write_text(
        "class Record:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    @property\n"
        "    def denominator(self) -> int:\n"
        "        return 1 if self.value == 0 else self.value\n\n"
        "def target(value: int) -> int:\n"
        "    return 10 // Record(value).denominator\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_preserves_readonly_property_bug_result(tmp_path: Path) -> None:
    target = tmp_path / "readonly_property_getter_bug.py"
    target.write_text(
        "class Record:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    @property\n"
        "    def denominator(self) -> int:\n"
        "        return self.value\n\n"
        "def target(value: int) -> int:\n"
        "    return 10 // Record(value).denominator\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_settable_property_getter_payload(
    tmp_path: Path,
) -> None:
    target = tmp_path / "settable_property_getter.py"
    target.write_text(
        "class Record:\n"
        "    @property\n"
        "    def value(self) -> int:\n"
        "        return 1\n\n"
        "    @value.setter\n"
        "    def value(self, new_value: int) -> None:\n"
        "        pass\n\n"
        "def target(value: int) -> int:\n"
        "    return 10 // Record().value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_safe_property_setter_payload(tmp_path: Path) -> None:
    target = tmp_path / "property_setter_safe.py"
    target.write_text(
        "class Record:\n"
        "    @property\n"
        "    def value(self) -> int:\n"
        "        return 1\n\n"
        "    @value.setter\n"
        "    def value(self, new_value: int) -> None:\n"
        "        10 // (1 if new_value == 0 else new_value)\n\n"
        "def target(value: int) -> None:\n"
        "    Record().value = value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_preserves_property_setter_bug_payload(tmp_path: Path) -> None:
    target = tmp_path / "property_setter_bug.py"
    target.write_text(
        "class Record:\n"
        "    @property\n"
        "    def value(self) -> int:\n"
        "        return 1\n\n"
        "    @value.setter\n"
        "    def value(self, new_value: int) -> None:\n"
        "        10 // new_value\n\n"
        "def target(value: int) -> None:\n"
        "    Record().value = value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_property_deleter_payload(tmp_path: Path) -> None:
    target = tmp_path / "property_deleter_bug.py"
    target.write_text(
        "class Record:\n"
        "    @property\n"
        "    def value(self) -> int:\n"
        "        return 1\n\n"
        "    @value.deleter\n"
        "    def value(self) -> None:\n"
        "        10 // 0\n\n"
        "def target() -> None:\n"
        "    del Record().value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_property_getter_payload_through_builtin(tmp_path: Path) -> None:
    target = tmp_path / "builtin_property_getter_bug.py"
    target.write_text(
        "class Record:\n"
        "    @property\n"
        "    def value(self) -> int:\n"
        "        return 0\n\n"
        "def target() -> int:\n"
        "    return 10 // getattr(Record(), 'value')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_property_setter_payload_through_builtin(tmp_path: Path) -> None:
    target = tmp_path / "builtin_property_setter_bug.py"
    target.write_text(
        "class Record:\n"
        "    @property\n"
        "    def value(self) -> int:\n"
        "        return 1\n\n"
        "    @value.setter\n"
        "    def value(self, new_value: int) -> None:\n"
        "        10 // new_value\n\n"
        "def target(value: int) -> None:\n"
        "    setattr(Record(), 'value', value)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_property_deleter_payload_through_builtin(tmp_path: Path) -> None:
    target = tmp_path / "builtin_property_deleter_bug.py"
    target.write_text(
        "class Record:\n"
        "    @property\n"
        "    def value(self) -> int:\n"
        "        return 1\n\n"
        "    @value.deleter\n"
        "    def value(self) -> None:\n"
        "        10 // 0\n\n"
        "def target() -> None:\n"
        "    delattr(Record(), 'value')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_getattr_default_with_successful_property(tmp_path: Path) -> None:
    target = tmp_path / "builtin_property_default_success.py"
    target.write_text(
        "class Record:\n"
        "    @property\n"
        "    def value(self) -> int:\n"
        "        return 0\n\n"
        "def target() -> int:\n"
        "    return 10 // getattr(Record(), 'value', 1)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_uses_getattr_default_after_property_attribute_error(tmp_path: Path) -> None:
    target = tmp_path / "builtin_property_default_error.py"
    target.write_text(
        "class Record:\n"
        "    @property\n"
        "    def value(self) -> int:\n"
        "        raise AttributeError('value')\n\n"
        "def target() -> int:\n"
        "    return 10 // getattr(Record(), 'value', 0)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_property_attribute_error_runs_getattr_before_default(tmp_path: Path) -> None:
    target = tmp_path / "builtin_property_getattr_default_success.py"
    target.write_text(
        "class Record:\n"
        "    @property\n"
        "    def value(self) -> int:\n"
        "        raise AttributeError('value')\n\n"
        "    def __getattr__(self, name: str) -> int:\n"
        "        return 1\n\n"
        "def target() -> int:\n"
        "    return 10 // getattr(Record(), 'value', 0)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_property_and_getattr_attribute_error_use_default(tmp_path: Path) -> None:
    target = tmp_path / "builtin_property_getattr_default_error.py"
    target.write_text(
        "class Record:\n"
        "    @property\n"
        "    def value(self) -> int:\n"
        "        raise AttributeError('value')\n\n"
        "    def __getattr__(self, name: str) -> int:\n"
        "        raise AttributeError(name)\n\n"
        "def target() -> int:\n"
        "    return 10 // getattr(Record(), 'value', 0)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_reports_value_error_from_property_setter(tmp_path: Path) -> None:
    target = tmp_path / "property_setter_value_error.py"
    target.write_text(
        "class Thermometer:\n"
        "    @property\n"
        "    def celsius(self) -> int:\n"
        "        return 0\n\n"
        "    @celsius.setter\n"
        "    def celsius(self, value: int) -> None:\n"
        "        if value < -273:\n"
        "            raise ValueError('below absolute zero')\n\n"
        "def target(value: int) -> None:\n"
        "    Thermometer().celsius = value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert any(
        issue.get("function_name") == "target"
        and issue.get("kind") == "VALUE_ERROR"
        and "ValueError" in str(issue.get("message", ""))
        for issue in result.issues
    )
