from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_preserves_custom_eq_bug_path(tmp_path: Path) -> None:
    target = tmp_path / "custom_eq_bug.py"
    target.write_text(
        "class Number:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __eq__(self, other: int) -> bool:\n"
        "        return self.value == other\n\n"
        "def target(value: int) -> int:\n"
        "    number = Number(value)\n"
        "    if number == 0:\n"
        "        return 1 // value\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("line") == 11
        for issue in result.issues
    )


def test_scan_file_uses_reflected_custom_eq_path(tmp_path: Path) -> None:
    target = tmp_path / "reflected_custom_eq_bug.py"
    target.write_text(
        "class Number:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __eq__(self, other: int) -> bool:\n"
        "        return self.value == other\n\n"
        "def target(value: int) -> int:\n"
        "    number = Number(value)\n"
        "    if 0 == number:\n"
        "        return 1 // value\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("line") == 11
        for issue in result.issues
    )


def test_scan_file_prioritizes_strict_subclass_reflected_ordering(tmp_path: Path) -> None:
    target = tmp_path / "subclass_reflected_ordering.py"
    target.write_text(
        "class Base:\n"
        "    def __lt__(self, other: object) -> bool:\n"
        "        return False\n\n"
        "class Child(Base):\n"
        "    def __gt__(self, other: object) -> bool:\n"
        "        return True\n\n"
        "def target() -> int:\n"
        "    if Base() < Child():\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_prioritizes_inherited_subclass_reflected_ordering(tmp_path: Path) -> None:
    target = tmp_path / "inherited_subclass_reflected_ordering.py"
    target.write_text(
        "class Base:\n"
        "    def __lt__(self, other: object) -> bool:\n"
        "        return False\n"
        "    def __gt__(self, other: object) -> bool:\n"
        "        return True\n\n"
        "class Child(Base):\n"
        "    pass\n\n"
        "def target() -> int:\n"
        "    if Base() < Child():\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_keeps_same_type_direct_ordering_before_reflection(tmp_path: Path) -> None:
    target = tmp_path / "same_type_reflected_ordering.py"
    target.write_text(
        "class Number:\n"
        "    def __lt__(self, other: object) -> bool:\n"
        "        return False\n"
        "    def __gt__(self, other: object) -> bool:\n"
        "        return True\n\n"
        "def target() -> int:\n"
        "    if Number() < Number():\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_prioritizes_strict_subclass_equality_method(tmp_path: Path) -> None:
    target = tmp_path / "subclass_equality.py"
    target.write_text(
        "class Base:\n"
        "    def __eq__(self, other: object) -> bool:\n"
        "        return False\n\n"
        "class Child(Base):\n"
        "    def __eq__(self, other: object) -> bool:\n"
        "        return True\n\n"
        "def target() -> int:\n"
        "    if Base() == Child():\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_completes_custom_eq_not_implemented_against_primitive(tmp_path: Path) -> None:
    target = tmp_path / "custom_eq_not_implemented.py"
    target.write_text(
        "class Number:\n"
        "    def __eq__(self, other: object) -> object:\n"
        "        return NotImplemented\n\n"
        "def target(value: int) -> int:\n"
        "    if Number() == value:\n"
        "        return 1 // value\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_comparison_reflection" not in result.degraded_passes
    assert not any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_completes_custom_ne_not_implemented_against_primitive(tmp_path: Path) -> None:
    target = tmp_path / "custom_ne_not_implemented.py"
    target.write_text(
        "class Number:\n"
        "    def __ne__(self, other: object) -> object:\n"
        "        return NotImplemented\n\n"
        "def target(value: int) -> int:\n"
        "    if Number() != value:\n"
        "        return 1 // value\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_comparison_reflection" not in result.degraded_passes
    assert not any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_continues_not_implemented_to_counterpart_comparison(
    tmp_path: Path,
) -> None:
    target = tmp_path / "custom_eq_not_implemented_counterpart.py"
    target.write_text(
        "class Left:\n"
        "    def __eq__(self, other: object) -> object:\n"
        "        return NotImplemented\n\n"
        "class Right:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __eq__(self, other: object) -> bool:\n"
        "        return self.value == 0\n\n"
        "def target(value: int) -> int:\n"
        "    if Left() == Right(value):\n"
        "        return 1 // value\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_comparison_reflection" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_completes_distinct_modeled_identity_comparison(
    tmp_path: Path,
) -> None:
    target = tmp_path / "custom_eq_not_implemented_distinct_instances.py"
    target.write_text(
        "class Left:\n"
        "    def __eq__(self, other: object) -> object:\n"
        "        return NotImplemented\n\n"
        "class Right:\n"
        "    def __eq__(self, other: object) -> object:\n"
        "        return NotImplemented\n\n"
        "def target(value: int) -> int:\n"
        "    if Left() == Right():\n"
        "        return 1 // value\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_comparison_reflection" not in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_completes_alias_modeled_identity_comparison(tmp_path: Path) -> None:
    target = tmp_path / "custom_eq_not_implemented_alias.py"
    target.write_text(
        "class Item:\n"
        "    def __eq__(self, other: object) -> object:\n"
        "        return NotImplemented\n\n"
        "def target(value: int) -> int:\n"
        "    item = Item()\n"
        "    alias = item\n"
        "    if item == alias:\n"
        "        return 1 // value\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_comparison_reflection" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_completes_distinct_modeled_inequality_comparison(
    tmp_path: Path,
) -> None:
    target = tmp_path / "custom_ne_not_implemented_distinct_instances.py"
    target.write_text(
        "class Left:\n"
        "    def __ne__(self, other: object) -> object:\n"
        "        return NotImplemented\n\n"
        "class Right:\n"
        "    def __ne__(self, other: object) -> object:\n"
        "        return NotImplemented\n\n"
        "def target(value: int) -> int:\n"
        "    if Left() != Right():\n"
        "        return 1 // value\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_comparison_reflection" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_reports_ordering_not_implemented_as_type_error(tmp_path: Path) -> None:
    target = tmp_path / "custom_lt_not_implemented.py"
    target.write_text(
        "class Number:\n"
        "    def __lt__(self, other: object) -> object:\n"
        "        return NotImplemented\n\n"
        "def target() -> bool:\n"
        "    return Number() < 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_comparison_reflection" not in result.degraded_passes
    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and "ordered comparison methods returned NotImplemented" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_reports_reflected_ordering_not_implemented_as_type_error(
    tmp_path: Path,
) -> None:
    target = tmp_path / "reflected_lt_not_implemented.py"
    target.write_text(
        "class Left:\n"
        "    def __lt__(self, other: object) -> object:\n"
        "        return NotImplemented\n\n"
        "class Right:\n"
        "    def __gt__(self, other: object) -> object:\n"
        "        return NotImplemented\n\n"
        "def target() -> bool:\n"
        "    return Left() < Right()\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_comparison_reflection" not in result.degraded_passes
    assert any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)
