"""Tests for scanner method-call semantics."""

from __future__ import annotations

from pathlib import Path
from pysymex.scanner.file import scan_file


def test_scan_file_reports_instance_method_returned_zero(tmp_path: Path) -> None:
    """Modeled method bodies should preserve returned zero bugs."""
    target = tmp_path / "instance_method_returned_zero.py"
    target.write_text(
        "class Record:\n"
        "    def echo(self, x: int) -> int:\n"
        "        return x\n\n"
        "def target(x: int) -> int:\n"
        "    obj = Record()\n"
        "    return 10 // obj.echo(x)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 7
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 7
        for issue in result.issues
    )


def test_scan_file_does_not_report_method_normalized_zero(tmp_path: Path) -> None:
    """Instance, static, and class methods should avoid havoc-return false positives."""
    target = tmp_path / "method_normalized_zero.py"
    target.write_text(
        "class Record:\n"
        "    def normalize(self, x: int) -> int:\n"
        "        if x == 0:\n"
        "            return 1\n"
        "        return x\n\n"
        "    @staticmethod\n"
        "    def static_normalize(x: int) -> int:\n"
        "        if x == 0:\n"
        "            return 1\n"
        "        return x\n\n"
        "    @classmethod\n"
        "    def class_normalize(cls, x: int) -> int:\n"
        "        if x == 0:\n"
        "            return 1\n"
        "        return x\n\n"
        "def target(x: int) -> int:\n"
        "    obj = Record()\n"
        "    return (\n"
        "        10 // obj.normalize(x)\n"
        "        + 10 // obj.static_normalize(x)\n"
        "        + 10 // obj.class_normalize(x)\n"
        "    )\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"DIVISION_BY_ZERO", "TYPE_ERROR"}
        and issue.get("function_name") == "target"
        and issue.get("line") in {22, 23, 24}
        for issue in result.issues
    )


def test_scan_file_does_not_report_class_level_method_normalized_zero(tmp_path: Path) -> None:
    """Class-level static/class method access should not become havoc-return bugs."""
    target = tmp_path / "class_level_method_normalized_zero.py"
    target.write_text(
        "class Record:\n"
        "    @staticmethod\n"
        "    def static_normalize(x: int) -> int:\n"
        "        if x == 0:\n"
        "            return 1\n"
        "        return x\n\n"
        "    @classmethod\n"
        "    def class_normalize(cls, x: int) -> int:\n"
        "        if x == 0:\n"
        "            return 1\n"
        "        return x\n\n"
        "def target(x: int) -> int:\n"
        "    return 10 // Record.static_normalize(x) + 10 // Record.class_normalize(x)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"DIVISION_BY_ZERO", "TYPE_ERROR"}
        and issue.get("function_name") == "target"
        and issue.get("line") == 15
        for issue in result.issues
    )


def test_scan_file_reports_class_level_instance_method_missing_self(tmp_path: Path) -> None:
    """Calling an instance method through the class without self should report TypeError."""
    target = tmp_path / "class_level_instance_method_missing_self.py"
    target.write_text(
        "class Record:\n"
        "    def normalize(self, x: int) -> int:\n"
        "        if x == 0:\n"
        "            return 1\n"
        "        return x\n\n"
        "def target(x: int) -> int:\n"
        "    return Record.normalize(x)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 8
        and "missing required argument 'x'" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_does_not_havoc_safe_top_level_helper_return(tmp_path: Path) -> None:
    """Concrete top-level helper functions should not become havoc-return false positives."""
    target = tmp_path / "safe_top_level_helper.py"
    target.write_text(
        "def _normalize(x: int) -> int:\n"
        "    if x == 0:\n"
        "        return 1\n"
        "    return x\n\n"
        "def target(x: int) -> int:\n"
        "    return 10 // _normalize(x)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"DIVISION_BY_ZERO", "TYPE_ERROR"}
        and issue.get("function_name") == "target"
        and issue.get("line") == 7
        for issue in result.issues
    )


def test_scan_file_reports_keyword_argument_helper_division(tmp_path: Path) -> None:
    """Keyword-bound helper parameters should preserve caller-linked bug paths."""
    target = tmp_path / "keyword_helper_bug.py"
    target.write_text(
        "def divide(denominator: int) -> int:\n"
        "    return 10 // denominator\n\n"
        "def target(x: int) -> int:\n"
        "    return divide(denominator=x)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 2
        for issue in result.issues
    )


def test_scan_file_does_not_report_guarded_keyword_argument_helper_division(
    tmp_path: Path,
) -> None:
    """A caller guard must constrain a keyword-bound helper denominator."""
    target = tmp_path / "keyword_helper_safe.py"
    target.write_text(
        "def divide(denominator: int) -> int:\n"
        "    return 10 // denominator\n\n"
        "def target(x: int) -> int:\n"
        "    if x == 0:\n"
        "        return 0\n"
        "    return divide(denominator=x)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 2
        for issue in result.issues
    )


def test_scan_file_preserves_reordered_keyword_helper_arguments(tmp_path: Path) -> None:
    """CALL_KW must bind values by keyword name rather than stack order."""
    target = tmp_path / "keyword_reordered_bug.py"
    target.write_text(
        "def divide(numerator: int, denominator: int) -> int:\n"
        "    return numerator // denominator\n\n"
        "def target(x: int) -> int:\n"
        "    return divide(denominator=x, numerator=10)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 2
        for issue in result.issues
    )


def test_scan_file_preserves_guard_for_reordered_keyword_helper_arguments(
    tmp_path: Path,
) -> None:
    """A guard on a reordered denominator must still rule out division by zero."""
    target = tmp_path / "keyword_reordered_safe.py"
    target.write_text(
        "def divide(numerator: int, denominator: int) -> int:\n"
        "    return numerator // denominator\n\n"
        "def target(x: int) -> int:\n"
        "    if x == 0:\n"
        "        return 0\n"
        "    return divide(denominator=x, numerator=10)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 2
        for issue in result.issues
    )


def test_scan_file_reports_partial_bound_helper_division(tmp_path: Path) -> None:
    target = tmp_path / "partial_helper_bug.py"
    target.write_text(
        "from functools import partial\n\n"
        "def divide(denominator: int) -> int:\n"
        "    return 10 // denominator\n\n"
        "def target(x: int) -> int:\n"
        "    denominator = 0 if x == 0 else 1\n"
        "    call = partial(divide, denominator)\n"
        "    return call()\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 4
        for issue in result.issues
    )


def test_scan_file_reports_module_qualified_partial_bound_division(tmp_path: Path) -> None:
    target = tmp_path / "qualified_partial_helper_bug.py"
    target.write_text(
        "import functools\n\n"
        "def target() -> int:\n"
        "    def divide(numerator: int, denominator: int) -> int:\n"
        "        return numerator // denominator\n"
        "    call = functools.partial(divide, denominator=0)\n"
        "    return call(10)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 5
        for issue in result.issues
    )


def test_scan_file_allows_guarded_partial_bound_helper_division(tmp_path: Path) -> None:
    target = tmp_path / "partial_helper_safe.py"
    target.write_text(
        "from functools import partial\n\n"
        "def divide(denominator: int) -> int:\n"
        "    return 10 // denominator\n\n"
        "def target(x: int) -> int:\n"
        "    denominator = 0 if x == 0 else 1\n"
        "    if denominator == 0:\n"
        "        return 0\n"
        "    call = partial(divide, denominator)\n"
        "    return call()\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 4
        for issue in result.issues
    )


def test_scan_file_standalone_method_self_uses_class_constructor_state(
    tmp_path: Path,
) -> None:
    """Standalone method scans should not treat typed constructor attributes as arbitrary."""
    target = tmp_path / "method_constructor_state.py"
    target.write_text(
        "class Holder:\n"
        "    def __init__(self, value: int = 0) -> None:\n"
        "        self.value = value\n\n"
        "    def invert(self) -> int:\n"
        "        return 1 // self.value\n\n"
        "def target() -> int:\n"
        "    return Holder().invert()\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") in {"invert", "target"}
        and issue.get("line") == 6
        for issue in result.issues
    )
    assert not any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)
