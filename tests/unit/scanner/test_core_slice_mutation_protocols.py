from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_executes_concrete_built_slice_store(tmp_path: Path) -> None:
    target = tmp_path / "built_slice_store_safe.py"
    target.write_text(
        "class Step:\n"
        "    def __index__(self) -> int:\n"
        "        return 2\n\n"
        "def target() -> int:\n"
        "    items = [0, 1, 0, 3]\n"
        "    items[0:4:Step()] = [1, 1]\n"
        "    return 10 // items[2]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert "unsupported_slice_abstraction" not in result.degraded_passes


def test_scan_file_reports_bytearray_slice_alias_zero_division(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_slice_alias_division.py"
    target.write_text(
        "def target(a: int, b: int, flag: int) -> int:\n"
        "    data = bytearray([7, 1, 3])\n"
        "    alias = data\n"
        "    if flag & 1:\n"
        "        alias[1:2] = bytes([(a - b) & 255])\n"
        "    else:\n"
        "        alias[1] = ((a - b) | 1) & 255\n"
        "    if flag == 1 and a == b:\n"
        "        return 100 // data[1]\n"
        "    return data[1] + 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert "unsupported_slice_abstraction" not in result.degraded_passes


def test_scan_file_executes_concrete_built_slice_delete(tmp_path: Path) -> None:
    target = tmp_path / "built_slice_delete_safe.py"
    target.write_text(
        "class Step:\n"
        "    def __index__(self) -> int:\n"
        "        return 2\n\n"
        "def target() -> int:\n"
        "    items = [0, 1, 0, 3]\n"
        "    del items[0:4:Step()]\n"
        "    return 10 // items[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"INDEX_ERROR", "DIVISION_BY_ZERO"} for issue in result.issues
    )
    assert "unsupported_slice_abstraction" not in result.degraded_passes


def test_scan_file_reports_concrete_extended_slice_store_length_error(tmp_path: Path) -> None:
    target = tmp_path / "built_slice_store_length_error.py"
    target.write_text(
        "def target() -> None:\n    items = [0, 1, 0, 3]\n    items[0:4:2] = [1]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "VALUE_ERROR"
        and "attempt to assign sequence of size 1 to extended slice of size 2"
        in str(issue.get("message"))
        for issue in result.issues
    )
    assert "unsupported_slice_abstraction" not in result.degraded_passes


def test_scan_file_reports_symbolic_zero_step_built_slice_store(tmp_path: Path) -> None:
    target = tmp_path / "symbolic_built_slice_store_zero_step.py"
    target.write_text(
        "def target(step: int) -> None:\n    items = [0, 1, 2]\n    items[::step] = [3]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "VALUE_ERROR"
        and "slice step cannot be zero" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_reports_symbolic_zero_step_built_slice_delete(tmp_path: Path) -> None:
    target = tmp_path / "symbolic_built_slice_delete_zero_step.py"
    target.write_text(
        "def target(step: int) -> None:\n    items = [0, 1, 2]\n    del items[::step]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "VALUE_ERROR"
        and "slice step cannot be zero" in str(issue.get("message"))
        for issue in result.issues
    )
