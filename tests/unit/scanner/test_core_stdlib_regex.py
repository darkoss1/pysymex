"""Scanner regressions for modeled regular-expression guards."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_reports_fullmatch_zero_denominator_without_parse_error(
    tmp_path: Path,
) -> None:
    target = tmp_path / "regex_zero_denominator.py"
    target.write_text(
        "import re\n"
        "\n"
        "def target(text: str) -> int:\n"
        "    if re.fullmatch(r'0+', text):\n"
        "        return 10 // int(text)\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 5
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") == "VALUE_ERROR" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_allows_fullmatch_nonzero_decimal_denominator(tmp_path: Path) -> None:
    target = tmp_path / "regex_nonzero_denominator.py"
    target.write_text(
        "import re\n"
        "\n"
        "def target(text: str) -> int:\n"
        "    if re.fullmatch(r'[1-9][0-9]*', text):\n"
        "        return 10 // int(text)\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"DIVISION_BY_ZERO", "VALUE_ERROR"}
        and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_reports_match_truthy_branch_division(tmp_path: Path) -> None:
    target = tmp_path / "regex_match_bug.py"
    target.write_text(
        "import re\n"
        "\n"
        "def target(text: str) -> int:\n"
        "    if re.match(r'0+', text) and text == '0':\n"
        "        return 10 // int(text)\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_allows_match_falsy_impossible_branch(tmp_path: Path) -> None:
    target = tmp_path / "regex_match_safe.py"
    target.write_text(
        "import re\n"
        "\n"
        "def target(text: str) -> int:\n"
        "    if not re.match(r'0+', text) and text == '0':\n"
        "        return 10 // int(text)\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_reports_search_truthy_branch_division(tmp_path: Path) -> None:
    target = tmp_path / "regex_search_bug.py"
    target.write_text(
        "import re\n"
        "\n"
        "def target(text: str) -> int:\n"
        "    if re.search(r'0+', text) and text == '0':\n"
        "        return 10 // int(text)\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_allows_search_falsy_impossible_branch(tmp_path: Path) -> None:
    target = tmp_path / "regex_search_safe.py"
    target.write_text(
        "import re\n"
        "\n"
        "def target(text: str) -> int:\n"
        "    if not re.search(r'0+', text) and text == '0':\n"
        "        return 10 // int(text)\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )
