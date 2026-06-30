"""Scanner regressions for symbolic string conversion exception paths."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


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


def test_scan_file_prunes_path_forced_symbolic_int_parse_mismatch(
    tmp_path: Path,
) -> None:
    """A path-forced string literal should parse exactly enough to kill impossible branches."""
    target = tmp_path / "symbolic_int_parse_mismatch.py"
    target.write_text(
        "def target(token: str) -> int:\n"
        "    if len(token) != 2:\n"
        "        return 1\n"
        "    if token[0] != '4' or token[1] != '2':\n"
        "        return 1\n"
        "    parsed = int(token)\n"
        "    if parsed == 43:\n"
        "        return 1 // 0\n"
        "    return parsed\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert result.issues == []
    assert result.degraded_passes == []


def test_scan_file_reports_path_forced_symbolic_int_parse_match(
    tmp_path: Path,
) -> None:
    """The same exact parse must still preserve recall for the reachable parsed value."""
    target = tmp_path / "symbolic_int_parse_match.py"
    target.write_text(
        "def target(token: str) -> int:\n"
        "    if len(token) != 2:\n"
        "        return 1\n"
        "    if token[0] != '4' or token[1] != '2':\n"
        "        return 1\n"
        "    parsed = int(token)\n"
        "    if parsed == 42:\n"
        "        return 1 // 0\n"
        "    return parsed\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert result.degraded_passes == []
    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
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
