"""Scanner regressions for ``ExceptionGroup`` and ``except*`` syntax."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


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


def test_scan_file_except_star_partial_group_lengths_stay_clean(tmp_path: Path) -> None:
    target = tmp_path / "exception_group_partial_lengths.py"
    target.write_text(
        "def helper() -> int:\n"
        "    score = 0\n"
        "    try:\n"
        "        raise ExceptionGroup('bad', [ValueError('x'), TypeError('y')])\n"
        "    except* ValueError as group:\n"
        "        score += len(group.exceptions)\n"
        "    except* TypeError as group:\n"
        "        score += 10 + len(group.exceptions)\n"
        "    return score\n"
        "\n"
        "\n"
        "def target() -> int:\n"
        "    return helper()\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert not any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)
    assert not any(issue.get("kind") == "UNHANDLED_EXCEPTION" for issue in result.issues)
    assert not any(issue.get("kind") == "SCAN_ERROR" for issue in result.issues)


def test_scan_file_nested_except_star_handlers_do_not_report_original_groups(
    tmp_path: Path,
) -> None:
    target = tmp_path / "nested_exception_group_handlers.py"
    target.write_text(
        "def target(flag: int) -> int:\n"
        "    total = 0\n"
        "    try:\n"
        "        try:\n"
        "            if flag:\n"
        "                raise ExceptionGroup('mixed', [ValueError('v'), RuntimeError('r')])\n"
        "            raise ExceptionGroup('only', [ValueError('v')])\n"
        "        except* ValueError as group:\n"
        "            total += len(group.exceptions)\n"
        "    except* RuntimeError as group:\n"
        "        total += len(group.exceptions) * 10\n"
        "    return total\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        max_paths=120,
        max_iterations=5000,
        timeout=8,
        no_cache=True,
    )

    assert not any(issue.get("kind") == "UNHANDLED_EXCEPTION" for issue in result.issues)
    assert not any(issue.get("kind") == "SCAN_ERROR" for issue in result.issues)


def test_scan_file_except_star_reraised_member_does_not_escape_original_group(
    tmp_path: Path,
) -> None:
    target = tmp_path / "exception_group_reraised_member.py"
    target.write_text(
        "def helper(mode: int) -> int:\n"
        "    score = 0\n"
        "    try:\n"
        "        if mode == 8:\n"
        "            raise ExceptionGroup('runtime', [ValueError('reroute')])\n"
        "    except* ValueError as group:\n"
        "        score += len(group.exceptions)\n"
        "        if mode == 8:\n"
        "            raise RuntimeError(group)\n"
        "    except* TypeError as group:\n"
        "        score += 10 + len(group.exceptions)\n"
        "    return score\n"
        "\n"
        "\n"
        "def target(mode: int) -> int:\n"
        "    if mode == 8:\n"
        "        return helper(8)\n"
        "    return mode\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert any(
        issue.get("kind") == "UNHANDLED_EXCEPTION" and "RuntimeError" in str(issue.get("message"))
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") == "UNHANDLED_EXCEPTION"
        and "Path raises unhandled exception: ExceptionGroup" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_except_star_nonmatching_direct_exception_stays_direct(
    tmp_path: Path,
) -> None:
    target = tmp_path / "except_star_direct_remainder.py"
    target.write_text(
        "def target() -> int:\n"
        "    marker = 0\n"
        "    try:\n"
        "        try:\n"
        "            raise LookupError('replacement')\n"
        "        except* ValueError as group:\n"
        "            marker += len(group.exceptions)\n"
        "    except LookupError:\n"
        "        marker = 5\n"
        "    return marker\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert not any(issue.get("kind") == "UNHANDLED_EXCEPTION" for issue in result.issues)
    assert not any(
        issue.get("kind") == "UNHANDLED_EXCEPTION" and "ExceptionGroup" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_except_star_nonmatching_zero_division_skips_group_body(
    tmp_path: Path,
) -> None:
    target = tmp_path / "except_star_direct_zero_division.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    score = 0\n"
        "    try:\n"
        "        score += 10 // value\n"
        "    except* ValueError as group:\n"
        "        score += len(group.exceptions)\n"
        "    return score\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert not any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)
