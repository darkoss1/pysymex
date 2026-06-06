"""Scanner regressions for ``ExceptionGroup`` and ``except*`` syntax."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def test_scan_file_handles_exception_group_except_star_without_crashing(tmp_path: Path) -> None:
    target = tmp_path / "exception_group_except_star.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    try:\n"
        "        if value == 0:\n"
        "            raise ExceptionGroup('bad', [ValueError('x'), TypeError('y')])\n"
        "    except* ValueError:\n"
        "        return 1\n"
        "    except* TypeError:\n"
        "        return 2\n"
        "    return 3\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "SCAN_ERROR" for issue in result.issues)


def test_scan_file_reports_uncaught_exception_group_without_crashing(tmp_path: Path) -> None:
    target = tmp_path / "exception_group_uncaught.py"
    target.write_text(
        "def target(value: int) -> None:\n"
        "    group = ExceptionGroup('bad', [ValueError('x'), TypeError('y')])\n"
        "    if value == 0:\n"
        "        raise group\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "UNHANDLED_EXCEPTION" for issue in result.issues)
    assert not any(issue.get("kind") == "SCAN_ERROR" for issue in result.issues)
