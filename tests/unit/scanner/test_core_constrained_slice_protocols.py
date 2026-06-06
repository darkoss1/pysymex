from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def test_scan_file_reads_built_slice_with_path_fixed_bound(tmp_path: Path) -> None:
    target = tmp_path / "constrained_built_slice_read.py"
    target.write_text(
        "def target(start: int) -> int:\n"
        "    if start == 1:\n"
        "        return 10 // [9, 0, 8][start:2:1][0]\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert "unsupported_slice_abstraction" not in result.degraded_passes


def test_scan_file_stores_built_slice_with_path_fixed_bound(tmp_path: Path) -> None:
    target = tmp_path / "constrained_built_slice_store.py"
    target.write_text(
        "def target(start: int) -> int:\n"
        "    items = [0, 0]\n"
        "    if start == 1:\n"
        "        items[start:2:1] = [1]\n"
        "        return 10 // items[1]\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert "unsupported_slice_abstraction" not in result.degraded_passes


def test_scan_file_deletes_built_slice_with_path_fixed_bound(tmp_path: Path) -> None:
    target = tmp_path / "constrained_built_slice_delete.py"
    target.write_text(
        "def target(start: int) -> int:\n"
        "    items = [1, 0, 3]\n"
        "    if start == 1:\n"
        "        del items[start:2:1]\n"
        "        return 10 // items[1]\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert "unsupported_slice_abstraction" not in result.degraded_passes
