from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def _issue_kinds(result: object) -> set[object]:
    return {issue.get("kind") for issue in getattr(result, "issues", [])}


def test_scan_file_descriptor_getter_preserves_closure_parameter_type(
    tmp_path: Path,
) -> None:
    target = tmp_path / "descriptor_getter_closure_bug.py"
    target.write_text(
        "def target(y: int) -> int:\n"
        "    class DividingDescriptor:\n"
        "        def __get__(self, instance: object, owner: object) -> int:\n"
        "            return 10 // y\n\n"
        "    class Box:\n"
        "        value = DividingDescriptor()\n\n"
        "    return Box().value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)
    issue_kinds = _issue_kinds(result)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert "DIVISION_BY_ZERO" in issue_kinds
    assert "ATTRIBUTE_ERROR" not in issue_kinds
    assert "TYPE_ERROR" not in issue_kinds


def test_scan_file_safe_descriptor_getter_preserves_closure_without_degradation(
    tmp_path: Path,
) -> None:
    target = tmp_path / "descriptor_getter_closure_safe.py"
    target.write_text(
        "def target(y: int) -> int:\n"
        "    class StableDescriptor:\n"
        "        def __get__(self, instance: object, owner: object) -> int:\n"
        "            return y + 4\n\n"
        "    class Box:\n"
        "        value = StableDescriptor()\n\n"
        "    return Box().value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)
    issue_kinds = _issue_kinds(result)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert "ATTRIBUTE_ERROR" not in issue_kinds
    assert "DIVISION_BY_ZERO" not in issue_kinds
    assert "TYPE_ERROR" not in issue_kinds


def test_scan_file_class_descriptor_getter_preserves_closure_parameter_type(
    tmp_path: Path,
) -> None:
    target = tmp_path / "class_descriptor_getter_closure_bug.py"
    target.write_text(
        "def target(y: int) -> int:\n"
        "    class DividingDescriptor:\n"
        "        def __get__(self, instance: object, owner: object) -> int:\n"
        "            return 10 // y\n\n"
        "    class Box:\n"
        "        value = DividingDescriptor()\n\n"
        "    return Box.value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)
    issue_kinds = _issue_kinds(result)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert "DIVISION_BY_ZERO" in issue_kinds
    assert "ATTRIBUTE_ERROR" not in issue_kinds
    assert "TYPE_ERROR" not in issue_kinds


def test_scan_file_safe_class_descriptor_getter_preserves_closure_without_degradation(
    tmp_path: Path,
) -> None:
    target = tmp_path / "class_descriptor_getter_closure_safe.py"
    target.write_text(
        "def target(y: int) -> int:\n"
        "    class StableDescriptor:\n"
        "        def __get__(self, instance: object, owner: object) -> int:\n"
        "            return y + 4\n\n"
        "    class Box:\n"
        "        value = StableDescriptor()\n\n"
        "    return Box.value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)
    issue_kinds = _issue_kinds(result)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert "ATTRIBUTE_ERROR" not in issue_kinds
    assert "DIVISION_BY_ZERO" not in issue_kinds
    assert "TYPE_ERROR" not in issue_kinds


def test_scan_file_getattr_class_descriptor_runs_getter(tmp_path: Path) -> None:
    target = tmp_path / "getattr_class_descriptor_getter.py"
    target.write_text(
        "def target(y: int) -> object:\n"
        "    class DividingDescriptor:\n"
        "        def __get__(self, instance: object, owner: object) -> int:\n"
        "            return 10 // y\n\n"
        "    class Box:\n"
        "        value = DividingDescriptor()\n\n"
        "    return getattr(Box, 'value')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)
    issue_kinds = _issue_kinds(result)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert "DIVISION_BY_ZERO" in issue_kinds
    assert "ATTRIBUTE_ERROR" not in issue_kinds
    assert "TYPE_ERROR" not in issue_kinds
