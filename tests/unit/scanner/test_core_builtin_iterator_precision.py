"""Scanner regressions for structured builtin iterator precision."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def _type_error_messages(result: object) -> list[str]:
    issues = getattr(result, "issues")
    return [str(issue.get("message")) for issue in issues if issue.get("kind") == "TYPE_ERROR"]


def test_scan_symbolic_enumerate_reversed_list_ints_without_type_error(tmp_path: Path) -> None:
    target = tmp_path / "enumerate_reversed_ints.py"
    target.write_text(
        "def target(xs: list[int]) -> int:\n"
        "    total = 0\n"
        "    for i, x in enumerate(reversed(xs)):\n"
        "        total += i + x\n"
        "    return total\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, max_paths=30, max_depth=400, max_iterations=2000)

    assert result.error is None
    assert not any(
        "Cannot concatenate 'str'" in message for message in _type_error_messages(result)
    )


def test_scan_symbolic_zip_map_abs_list_ints_without_type_error(tmp_path: Path) -> None:
    target = tmp_path / "zip_map_abs_ints.py"
    target.write_text(
        "def target(xs: list[int]) -> int:\n"
        "    total = 0\n"
        "    for a, b in zip(xs, map(abs, xs)):\n"
        "        total += a + b\n"
        "    return total\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, max_paths=30, max_depth=400, max_iterations=2000)

    assert result.error is None
    assert not any(
        "Cannot concatenate 'str'" in message for message in _type_error_messages(result)
    )
