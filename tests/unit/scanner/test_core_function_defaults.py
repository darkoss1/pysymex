"""Scanner regressions for interprocedural Python default-argument binding."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_binds_omitted_positional_default_in_callee(tmp_path: Path) -> None:
    target = tmp_path / "omitted_positional_default.py"
    target.write_text(
        "def divide(denominator: int = 1) -> int:\n"
        "    return 10 // denominator\n\n"
        "def target() -> int:\n"
        "    return divide()\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("function_name") == "target"
        and issue.get("kind") in {"DIVISION_BY_ZERO", "UNBOUND_VARIABLE", "TYPE_ERROR"}
        for issue in result.issues
    )


def test_scan_file_preserves_explicit_positional_default_override_bug(tmp_path: Path) -> None:
    target = tmp_path / "positional_default_override.py"
    target.write_text(
        "def divide(denominator: int = 1) -> int:\n"
        "    return 10 // denominator\n\n"
        "def target() -> int:\n"
        "    return divide(0)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("function_name") == "target"
        and issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("line") == 2
        for issue in result.issues
    )


def test_scan_file_binds_omitted_keyword_only_default_in_callee(tmp_path: Path) -> None:
    target = tmp_path / "omitted_keyword_only_default.py"
    target.write_text(
        "def divide(*, denominator: int = 1) -> int:\n"
        "    return 10 // denominator\n\n"
        "def target() -> int:\n"
        "    return divide()\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("function_name") == "target"
        and issue.get("kind") in {"DIVISION_BY_ZERO", "UNBOUND_VARIABLE", "TYPE_ERROR"}
        for issue in result.issues
    )


def test_scan_file_preserves_explicit_keyword_only_default_override_bug(tmp_path: Path) -> None:
    target = tmp_path / "keyword_only_default_override.py"
    target.write_text(
        "def divide(*, denominator: int = 1) -> int:\n"
        "    return 10 // denominator\n\n"
        "def target() -> int:\n"
        "    return divide(denominator=0)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("function_name") == "target"
        and issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("line") == 2
        for issue in result.issues
    )


def test_scan_file_preserves_imported_builtin_default_callable(tmp_path: Path) -> None:
    target = tmp_path / "imported_builtin_default_callable.py"
    target.write_text(
        "from builtins import int as builtin_int\n\n"
        "def parse(value: object, converter: object = builtin_int) -> int:\n"
        "    return converter(value)\n\n"
        "def target() -> int:\n"
        "    return parse('not-an-int')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert any(
        issue.get("function_name") == "target" and issue.get("kind") == "VALUE_ERROR"
        for issue in result.issues
    )
    assert not any(
        issue.get("function_name") == "target" and issue.get("kind") == "TYPE_ERROR"
        for issue in result.issues
    )
