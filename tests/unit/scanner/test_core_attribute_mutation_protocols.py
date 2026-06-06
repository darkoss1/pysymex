from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def test_scan_file_executes_safe_custom_setattr_body(tmp_path: Path) -> None:
    target = tmp_path / "custom_setattr_safe.py"
    target.write_text(
        "class Box:\n"
        "    def __setattr__(self, name: str, value: int) -> None:\n"
        "        if name == 'value':\n"
        "            10 // (1 if value == 0 else value)\n\n"
        "def target(value: int) -> None:\n"
        "    Box().value = value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_preserves_custom_setattr_bug_body(tmp_path: Path) -> None:
    target = tmp_path / "custom_setattr_bug.py"
    target.write_text(
        "class Box:\n"
        "    def __setattr__(self, name: str, value: int) -> None:\n"
        "        if name == 'value':\n"
        "            10 // value\n\n"
        "def target(value: int) -> None:\n"
        "    Box().value = value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_custom_delattr_body(tmp_path: Path) -> None:
    target = tmp_path / "custom_delattr_bug.py"
    target.write_text(
        "class Box:\n"
        "    def __delattr__(self, name: str) -> None:\n"
        "        10 // 0\n\n"
        "def target() -> None:\n"
        "    del Box().value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert not any(issue.get("kind") == "ATTRIBUTE_ERROR" for issue in result.issues)


def test_scan_file_clean_custom_delattr_has_no_attribute_error(tmp_path: Path) -> None:
    target = tmp_path / "custom_delattr_clean.py"
    target.write_text(
        "class Box:\n"
        "    def __delattr__(self, name: str) -> None:\n"
        "        return None\n\n"
        "def target(y: int) -> int:\n"
        "    box = Box()\n"
        "    del box.value\n"
        "    return y\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "ATTRIBUTE_ERROR" for issue in result.issues)
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_safe_custom_setattr_body_through_builtin(tmp_path: Path) -> None:
    target = tmp_path / "builtin_custom_setattr_safe.py"
    target.write_text(
        "class Box:\n"
        "    def __setattr__(self, name: str, value: int) -> None:\n"
        "        10 // (1 if value == 0 else value)\n\n"
        "def target(value: int) -> None:\n"
        "    setattr(Box(), 'value', value)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_preserves_custom_setattr_bug_body_through_builtin(tmp_path: Path) -> None:
    target = tmp_path / "builtin_custom_setattr_bug.py"
    target.write_text(
        "class Box:\n"
        "    def __setattr__(self, name: str, value: int) -> None:\n"
        "        10 // value\n\n"
        "def target(value: int) -> None:\n"
        "    setattr(Box(), 'value', value)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_custom_delattr_body_through_builtin(tmp_path: Path) -> None:
    target = tmp_path / "builtin_custom_delattr_bug.py"
    target.write_text(
        "class Box:\n"
        "    def __delattr__(self, name: str) -> None:\n"
        "        10 // 0\n\n"
        "def target() -> None:\n"
        "    delattr(Box(), 'value')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert not any(issue.get("kind") == "ATTRIBUTE_ERROR" for issue in result.issues)
