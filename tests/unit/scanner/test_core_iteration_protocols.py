from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def test_scan_file_executes_safe_first_custom_next_result(tmp_path: Path) -> None:
    target = tmp_path / "custom_iterator_safe.py"
    target.write_text(
        "class Items:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __iter__(self) -> 'Items':\n"
        "        return self\n\n"
        "    def __next__(self) -> int:\n"
        "        return 1\n\n"
        "def target(value: int) -> int:\n"
        "    for item in Items(value):\n"
        "        return 10 // item\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_preserves_first_custom_next_bug_result(tmp_path: Path) -> None:
    target = tmp_path / "custom_iterator_bug.py"
    target.write_text(
        "class Items:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __iter__(self) -> 'Items':\n"
        "        return self\n\n"
        "    def __next__(self) -> int:\n"
        "        return self.value\n\n"
        "def target(value: int) -> int:\n"
        "    for item in Items(value):\n"
        "        return 10 // item\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_preserves_guarded_custom_next_result_through_iter(tmp_path: Path) -> None:
    target = tmp_path / "custom_iterator_guarded_safe.py"
    target.write_text(
        "class Items:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __iter__(self) -> 'Items':\n"
        "        return self\n\n"
        "    def __next__(self) -> int:\n"
        "        return 1 if self.value == 0 else self.value\n\n"
        "def target(value: int) -> int:\n"
        "    for item in Items(value):\n"
        "        return 10 // item\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues), (
        result.issues
    )


def test_scan_file_reports_non_iterator_custom_iter_result(tmp_path: Path) -> None:
    target = tmp_path / "custom_iterator_invalid.py"
    target.write_text(
        "class Items:\n"
        "    def __iter__(self) -> int:\n"
        "        return 1\n\n"
        "def target() -> int:\n"
        "    for item in Items():\n"
        "        return item\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and "iter() returned non-iterator" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_executes_explicit_custom_iter_builtin(tmp_path: Path) -> None:
    target = tmp_path / "custom_iter_builtin_safe.py"
    target.write_text(
        "class Items:\n"
        "    def __iter__(self) -> 'Items':\n"
        "        return self\n\n"
        "    def __next__(self) -> int:\n"
        "        return 1\n\n"
        "def target(value: int) -> int:\n"
        "    for item in iter(Items()):\n"
        "        return 10 // item\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_explicit_custom_next_builtin(tmp_path: Path) -> None:
    target = tmp_path / "custom_next_builtin_safe.py"
    target.write_text(
        "class Items:\n"
        "    def __next__(self) -> int:\n"
        "        return 1\n\n"
        "def target(value: int) -> int:\n"
        "    return 10 // next(Items())\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_custom_reversed_builtin(tmp_path: Path) -> None:
    target = tmp_path / "custom_reversed_builtin_safe.py"
    target.write_text(
        "class Items:\n"
        "    def __reversed__(self) -> tuple[int, ...]:\n"
        "        return (1,)\n\n"
        "def target(value: int) -> int:\n"
        "    for item in reversed(Items()):\n"
        "        return 10 // item\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
