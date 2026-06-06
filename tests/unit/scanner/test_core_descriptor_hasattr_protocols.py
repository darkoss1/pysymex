from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def test_scan_file_descriptor_hasattr_is_true_even_when_getter_returns_zero(
    tmp_path: Path,
) -> None:
    target = tmp_path / "descriptor_hasattr_true_zero.py"
    target.write_text(
        "class Value:\n"
        "    def __get__(self, obj, owner) -> int:\n"
        "        return 0\n\n"
        "class Record:\n"
        "    value = Value()\n\n"
        "def target() -> int:\n"
        "    if hasattr(Record(), 'value'):\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_descriptor_hasattr_is_false_after_attribute_error(tmp_path: Path) -> None:
    target = tmp_path / "descriptor_hasattr_attribute_error.py"
    target.write_text(
        "class Value:\n"
        "    def __get__(self, obj, owner) -> int:\n"
        "        raise AttributeError('value')\n\n"
        "class Record:\n"
        "    value = Value()\n\n"
        "def target() -> int:\n"
        "    if hasattr(Record(), 'value'):\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_descriptor_hasattr_executes_getter_body(tmp_path: Path) -> None:
    target = tmp_path / "descriptor_hasattr_getter_bug.py"
    target.write_text(
        "class Value:\n"
        "    def __get__(self, obj, owner) -> int:\n"
        "        return 10 // 0\n\n"
        "class Record:\n"
        "    value = Value()\n\n"
        "def target() -> bool:\n"
        "    return hasattr(Record(), 'value')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_descriptor_hasattr_respects_non_data_instance_shadowing(
    tmp_path: Path,
) -> None:
    target = tmp_path / "descriptor_hasattr_shadowing.py"
    target.write_text(
        "class Value:\n"
        "    def __get__(self, obj, owner) -> int:\n"
        "        return 10 // 0\n\n"
        "class Record:\n"
        "    value = Value()\n\n"
        "    def __init__(self) -> None:\n"
        "        self.value = 1\n\n"
        "def target() -> bool:\n"
        "    return hasattr(Record(), 'value')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_descriptor_hasattr_degrades_stateful_descriptor(tmp_path: Path) -> None:
    target = tmp_path / "descriptor_hasattr_stateful.py"
    target.write_text(
        "class Value:\n"
        "    def __init__(self) -> None:\n"
        "        self.result = 1\n\n"
        "    def __get__(self, obj, owner) -> int:\n"
        "        return self.result\n\n"
        "class Record:\n"
        "    value = Value()\n\n"
        "def target() -> bool:\n"
        "    return hasattr(Record(), 'value')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_descriptor_hasattr_does_not_filter_warning_after_resource_limit(
    tmp_path: Path,
) -> None:
    target = tmp_path / "descriptor_hasattr_limited.py"
    target.write_text(
        "class Value:\n"
        "    def __get__(self, obj, owner) -> int:\n"
        "        raise AttributeError('value')\n\n"
        "class Record:\n"
        "    value = Value()\n\n"
        "def target() -> int:\n"
        "    if hasattr(Record(), 'value'):\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, max_iterations=1)

    assert "resource_limit_iterations" in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
