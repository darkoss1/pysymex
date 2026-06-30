"""Scanner regressions for descriptor ``owner`` argument execution."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import cast

from pysymex._internal.scanner.file import scan_file


def _issue_kind(issue: object) -> object:
    if isinstance(issue, dict):
        return cast("Mapping[str, object]", issue).get("kind")
    raw_kind = getattr(issue, "kind", None)
    return getattr(raw_kind, "name", raw_kind)


def _scan_source(tmp_path: Path, filename: str, source: str):
    target = tmp_path / filename
    target.write_text(source, encoding="utf-8")
    return scan_file(
        target,
        max_paths=120,
        timeout=8,
        use_sandbox=False,
        no_cache=True,
        max_iterations=10000,
    )


def test_scan_file_nested_descriptor_owner_read_reports_feasible_bug(
    tmp_path: Path,
) -> None:
    """Nested descriptors may use the CPython ``owner`` argument directly."""
    result = _scan_source(
        tmp_path,
        "nested_descriptor_owner_read_bug.py",
        """
def target() -> int:
    class Slot:
        def __get__(self, instance, owner) -> int:
            return owner.zero

    class Box:
        zero = 0
        denom = Slot()

    return 100 // Box().denom
""",
    )

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert any(_issue_kind(issue) == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_nested_descriptor_owner_read_safe_control(
    tmp_path: Path,
) -> None:
    """Owner reads should not invent a bug when CPython returns a safe value."""
    result = _scan_source(
        tmp_path,
        "nested_descriptor_owner_read_safe.py",
        """
def target() -> int:
    class Slot:
        def __get__(self, instance, owner) -> int:
            return owner.one

    class Box:
        one = 1
        denom = Slot()

    return 100 // Box().denom
""",
    )

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert not any(_issue_kind(issue) == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_nested_descriptor_owner_read_attribute_error_fallback(
    tmp_path: Path,
) -> None:
    """Owner reads must not suppress descriptor ``AttributeError`` fallback."""
    result = _scan_source(
        tmp_path,
        "nested_descriptor_owner_read_getattr_fallback.py",
        """
def target() -> int:
    class Slot:
        def __get__(self, instance, owner):
            if owner is not None:
                pass
            raise AttributeError("denom")

    class Box:
        denom = Slot()

        def __getattr__(self, name: str) -> int:
            if name == "denom":
                return 0
            raise AttributeError(name)

    return 100 // Box().denom
""",
    )

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert any(_issue_kind(issue) == "DIVISION_BY_ZERO" for issue in result.issues)
    assert not any(_issue_kind(issue) == "ATTRIBUTE_ERROR" for issue in result.issues)
