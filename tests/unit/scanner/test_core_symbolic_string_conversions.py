"""Scanner regressions for symbolic string conversion exception paths."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def test_scan_file_detects_none_misuse_after_caught_symbolic_int_parse(
    tmp_path: Path,
) -> None:
    """A symbolic int() parse failure should flow through except to None misuse."""
    target = tmp_path / "symbolic_int_parse_none.py"
    target.write_text(
        "def target(token: str) -> int:\n"
        "    try:\n"
        "        parsed = int(token)\n"
        "    except ValueError:\n"
        "        parsed = None\n"
        "    return parsed * 2\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 6
        and "NoneType" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_does_not_report_guarded_caught_symbolic_int_parse(
    tmp_path: Path,
) -> None:
    """A None guard after caught int() failure should prevent a false TypeError."""
    target = tmp_path / "symbolic_int_parse_guarded.py"
    target.write_text(
        "def target(token: str) -> int:\n"
        "    try:\n"
        "        parsed = int(token)\n"
        "    except ValueError:\n"
        "        parsed = None\n"
        "    if parsed is None:\n"
        "        return 0\n"
        "    return parsed * 2\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 8
        for issue in result.issues
    )


def test_scan_file_detects_none_misuse_after_caught_symbolic_float_parse(
    tmp_path: Path,
) -> None:
    """A symbolic float() parse failure should flow through except to None misuse."""
    target = tmp_path / "symbolic_float_parse_none.py"
    target.write_text(
        "def target(token: str) -> float:\n"
        "    try:\n"
        "        parsed = float(token)\n"
        "    except ValueError:\n"
        "        parsed = None\n"
        "    return parsed * 2\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 6
        and "NoneType" in str(issue.get("message"))
        for issue in result.issues
    )
