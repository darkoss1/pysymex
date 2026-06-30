from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_uses_module_initialized_shared_defaults(tmp_path: Path) -> None:
    target = tmp_path / "default_alias_scan.py"
    target.write_text(
        """
SHARED: list[int] = []

def helper(x: int, xs: list[int] = SHARED, ys: list[int] = SHARED) -> int:
    if x == 0:
        ys.append(1)
    return len(xs)

def target(x: int) -> int:
    size = helper(x)
    if size > 0:
        return 10 // x
    return 1
""",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, timeout=10, max_paths=80, no_cache=True)

    assert any(issue["kind"] == "DIVISION_BY_ZERO" for issue in result.issues)
    assert not any("missing required argument" in str(issue["message"]) for issue in result.issues)
    assert result.error is None


def test_scan_file_uses_safe_default_object_attribute_container(tmp_path: Path) -> None:
    target = tmp_path / "default_object_attr_scan.py"
    target.write_text(
        """
class Box:
    def __init__(self) -> None:
        self.items = []

SHARED = Box()
ALIAS = SHARED

def helper(x: int, box: Box = SHARED, alias: Box = ALIAS) -> int:
    if x == 0:
        alias.items.append(x)
        return 10 // x
    return len(box.items)
""",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, timeout=10, max_paths=80, no_cache=True)

    assert any(issue["kind"] == "DIVISION_BY_ZERO" for issue in result.issues)
    assert not any("missing required argument" in str(issue["message"]) for issue in result.issues)
    assert not any(issue["kind"] == "ATTRIBUTE_ERROR" for issue in result.issues)
    assert result.error is None


def test_scan_file_does_not_execute_constructor_body_for_default_object(
    tmp_path: Path,
) -> None:
    target = tmp_path / "unsafe_default_object_attr_scan.py"
    target.write_text(
        """
class Box:
    def __init__(self) -> None:
        self.items = list()

SHARED = Box()

def helper(x: int, box: Box = SHARED) -> int:
    box.items.append(x)
    return len(box.items)

def target(x: int) -> int:
    size = helper(x)
    if size > 0:
        return 10 // x
    return 1
""",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, timeout=10, max_paths=80, no_cache=True)

    assert not any(issue["kind"] == "DIVISION_BY_ZERO" for issue in result.issues)
    assert any("missing required argument" in str(issue["message"]) for issue in result.issues)
    assert result.error is None
