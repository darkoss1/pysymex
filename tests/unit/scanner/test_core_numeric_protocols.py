from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def test_scan_file_respects_safe_custom_add_result(tmp_path: Path) -> None:
    target = tmp_path / "custom_add_safe.py"
    target.write_text(
        "class Number:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __add__(self, other: int) -> int:\n"
        "        return 1 if self.value == 0 else self.value\n\n"
        "def target(value: int) -> int:\n"
        "    return 10 // (Number(value) + 0)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_uses_safe_reflected_add_result(tmp_path: Path) -> None:
    target = tmp_path / "reflected_add_safe.py"
    target.write_text(
        "class Number:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __radd__(self, other: int) -> int:\n"
        "        return 1 if self.value == 0 else self.value\n\n"
        "def target(value: int) -> int:\n"
        "    return 10 // (0 + Number(value))\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_prioritizes_strict_subclass_reflected_add(tmp_path: Path) -> None:
    target = tmp_path / "subclass_reflected_add.py"
    target.write_text(
        "class Base:\n"
        "    def __add__(self, other: object) -> int:\n"
        "        return 1\n\n"
        "class Child(Base):\n"
        "    def __radd__(self, other: object) -> int:\n"
        "        return 0\n\n"
        "def target() -> int:\n"
        "    return 10 // (Base() + Child())\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_numeric_reflection" not in result.degraded_passes
    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_keeps_same_type_direct_add_before_reflection(tmp_path: Path) -> None:
    target = tmp_path / "same_type_reflected_add.py"
    target.write_text(
        "class Number:\n"
        "    def __add__(self, other: object) -> int:\n"
        "        return 1\n\n"
        "    def __radd__(self, other: object) -> int:\n"
        "        return 0\n\n"
        "def target() -> int:\n"
        "    return 10 // (Number() + Number())\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_does_not_prioritize_inherited_reflected_add(tmp_path: Path) -> None:
    target = tmp_path / "inherited_reflected_add.py"
    target.write_text(
        "class Base:\n"
        "    def __add__(self, other: object) -> int:\n"
        "        return 1\n"
        "    def __radd__(self, other: object) -> int:\n"
        "        return 0\n\n"
        "class Child(Base):\n"
        "    pass\n\n"
        "def target() -> int:\n"
        "    return 10 // (Base() + Child())\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_prioritizes_custom_inplace_add(tmp_path: Path) -> None:
    target = tmp_path / "inplace_add_safe.py"
    target.write_text(
        "class Number:\n"
        "    def __iadd__(self, other: int) -> int:\n"
        "        return 1\n\n"
        "    def __add__(self, other: int) -> int:\n"
        "        return 0\n\n"
        "def target() -> int:\n"
        "    value = Number()\n"
        "    value += 0\n"
        "    return 10 // value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_passes_same_instance_as_explicit_custom_add_argument(tmp_path: Path) -> None:
    target = tmp_path / "same_instance_add_safe.py"
    target.write_text(
        "class Number:\n"
        "    def __add__(self, other: object) -> int:\n"
        "        return 1\n\n"
        "def target() -> int:\n"
        "    number = Number()\n"
        "    return 10 // (number + number)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_reports_plain_class_numeric_not_implemented_as_type_error(
    tmp_path: Path,
) -> None:
    target = tmp_path / "custom_add_not_implemented.py"
    target.write_text(
        "class Number:\n"
        "    def __add__(self, other: object) -> object:\n"
        "        return NotImplemented\n\n"
        "def target(value: int) -> int:\n"
        "    result = Number() + value\n"
        "    return value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_numeric_reflection" not in result.degraded_passes
    assert any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)


def test_scan_file_reports_plain_class_primitive_sub_reflection_as_type_error(
    tmp_path: Path,
) -> None:
    target = tmp_path / "custom_sub_not_implemented.py"
    target.write_text(
        "class Number:\n"
        "    def __sub__(self, other: object) -> object:\n"
        "        return NotImplemented\n\n"
        "def target(value: int) -> int:\n"
        "    result = Number() - value\n"
        "    return value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_numeric_reflection" not in result.degraded_passes
    assert any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)


def test_scan_file_reports_plain_reflected_add_not_implemented_as_type_error(
    tmp_path: Path,
) -> None:
    target = tmp_path / "reflected_add_not_implemented.py"
    target.write_text(
        "class Number:\n"
        "    def __radd__(self, other: object) -> object:\n"
        "        return NotImplemented\n\n"
        "def target(value: int) -> object:\n"
        "    return value + Number()\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_numeric_reflection" not in result.degraded_passes
    assert any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)


def test_scan_file_does_not_report_native_subclass_reflection_as_type_error(
    tmp_path: Path,
) -> None:
    target = tmp_path / "native_subclass_add_not_implemented.py"
    target.write_text(
        "class Number(int):\n"
        "    def __add__(self, other: object) -> object:\n"
        "        return NotImplemented\n\n"
        "def target() -> object:\n"
        "    return Number(3) + 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_numeric_reflection" in result.degraded_passes
    assert not any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)


def test_scan_file_reports_exhausted_modeled_add_as_type_error(tmp_path: Path) -> None:
    target = tmp_path / "modeled_add_not_implemented.py"
    target.write_text(
        "class Left:\n"
        "    def __add__(self, other: object) -> object:\n"
        "        return NotImplemented\n\n"
        "class Right:\n"
        "    def __radd__(self, other: object) -> object:\n"
        "        return NotImplemented\n\n"
        "def target() -> object:\n"
        "    return Left() + Right()\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_numeric_reflection" not in result.degraded_passes
    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and "numeric methods returned NotImplemented" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_continues_not_implemented_to_reflected_add(tmp_path: Path) -> None:
    target = tmp_path / "numeric_not_implemented_reflected_safe.py"
    target.write_text(
        "class Left:\n"
        "    def __add__(self, other: object) -> object:\n"
        "        return NotImplemented\n\n"
        "class Right:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __radd__(self, other: object) -> int:\n"
        "        return 1 if self.value == 0 else self.value\n\n"
        "def target(value: int) -> int:\n"
        "    return 10 // (Left() + Right(value))\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_numeric_reflection" not in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_continues_not_implemented_inplace_to_direct_add(tmp_path: Path) -> None:
    target = tmp_path / "inplace_not_implemented_direct_safe.py"
    target.write_text(
        "class Number:\n"
        "    def __iadd__(self, other: int) -> object:\n"
        "        return NotImplemented\n\n"
        "    def __add__(self, other: int) -> int:\n"
        "        return 1\n\n"
        "def target() -> int:\n"
        "    number = Number()\n"
        "    number += 0\n"
        "    return 10 // number\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_numeric_reflection" not in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_preserves_mutation_before_inplace_fallback(tmp_path: Path) -> None:
    target = tmp_path / "inplace_not_implemented_mutation_safe.py"
    target.write_text(
        "class Number:\n"
        "    def __init__(self) -> None:\n"
        "        self.value = 0\n\n"
        "    def __iadd__(self, other: int) -> object:\n"
        "        self.value = 1\n"
        "        return NotImplemented\n\n"
        "    def __add__(self, other: int) -> int:\n"
        "        return self.value\n\n"
        "def target() -> int:\n"
        "    number = Number()\n"
        "    number += 0\n"
        "    return 10 // number\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_numeric_reflection" not in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_reports_exhausted_modeled_inplace_add_as_type_error(tmp_path: Path) -> None:
    target = tmp_path / "modeled_inplace_add_not_implemented.py"
    target.write_text(
        "class Left:\n"
        "    def __iadd__(self, other: object) -> object:\n"
        "        return NotImplemented\n\n"
        "    def __add__(self, other: object) -> object:\n"
        "        return NotImplemented\n\n"
        "class Right:\n"
        "    def __radd__(self, other: object) -> object:\n"
        "        return NotImplemented\n\n"
        "def target() -> object:\n"
        "    left = Left()\n"
        "    left += Right()\n"
        "    return left\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_numeric_reflection" not in result.degraded_passes
    assert any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)
