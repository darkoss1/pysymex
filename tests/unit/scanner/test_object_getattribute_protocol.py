"""Scanner regressions for exact ``object.__getattribute__`` lookup."""

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
        timeout=30,
        use_sandbox=False,
        no_cache=True,
        max_iterations=10000,
    )


_OBJECT_GETATTRIBUTE_DESCRIPTOR_FALLBACK = """
class Slot:
    def __get__(self, instance, owner):
        instance.events.append("slot")
        raise AttributeError("denom")


class Box:
    denom = Slot()

    def __init__(self, seed: int, d: int, e: int):
        self.seed = seed
        self.d = d
        self.e = e
        self.events = []

    def __getattribute__(self, name: str):
        if name == "denom":
            events = object.__getattribute__(self, "events")
            events.append("getattribute")
            return object.__getattribute__(self, name)
        return object.__getattribute__(self, name)

    def __getattr__(self, name: str) -> int:
        if name == "denom":
            d = object.__getattribute__(self, "d")
            e = object.__getattribute__(self, "e")
            if d == e:
                return d - e
            return d + 1
        raise AttributeError(name)
"""


def test_scan_file_object_getattribute_descriptor_error_chains_to_getattr(
    tmp_path: Path,
) -> None:
    """Base-object descriptor failure must retain CPython ``__getattr__`` fallback."""
    result = _scan_source(
        tmp_path,
        "object_getattribute_descriptor_getattr_bug.py",
        _OBJECT_GETATTRIBUTE_DESCRIPTOR_FALLBACK
        + """
def target(a: int, b: int, d: int, e: int) -> int:
    box = Box(a + b, d, e)
    if a > b:
        box.events.append("left")
    else:
        box.events.append("right")
    return 100 // box.denom
""",
    )

    assert any(_issue_kind(issue) == "DIVISION_BY_ZERO" for issue in result.issues)
    assert not any(_issue_kind(issue) == "ATTRIBUTE_ERROR" for issue in result.issues)
    assert not result.degraded_passes


def test_scan_file_object_getattribute_descriptor_error_guarded_control(
    tmp_path: Path,
) -> None:
    """Guarded fallback result must not produce invented division or attribute errors."""
    result = _scan_source(
        tmp_path,
        "object_getattribute_descriptor_getattr_guarded.py",
        _OBJECT_GETATTRIBUTE_DESCRIPTOR_FALLBACK
        + """
def target(a: int, b: int, d: int, e: int) -> int:
    box = Box(a + b, d, e)
    denom = box.denom
    if denom == 0:
        denom = 1
    return 100 // denom
""",
    )

    assert not any(
        _issue_kind(issue) in {"DIVISION_BY_ZERO", "ATTRIBUTE_ERROR", "TYPE_ERROR"}
        for issue in result.issues
    )
    assert not result.degraded_passes


def test_scan_file_object_getattribute_preserves_non_attribute_error(
    tmp_path: Path,
) -> None:
    """Only ``AttributeError`` should trigger the CPython ``__getattr__`` fallback chain."""
    result = _scan_source(
        tmp_path,
        "object_getattribute_value_error.py",
        """
class Slot:
    def __get__(self, instance, owner):
        raise ValueError("denom")


class Box:
    denom = Slot()

    def __getattribute__(self, name: str):
        return object.__getattribute__(self, name)

    def __getattr__(self, name: str) -> int:
        return 0


def target() -> int:
    return 100 // Box().denom
""",
    )

    assert any(_issue_kind(issue) == "VALUE_ERROR" for issue in result.issues)
    assert not any(_issue_kind(issue) == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_arbitrary_concrete_getattribute_stays_blocked(
    tmp_path: Path,
) -> None:
    """The concrete-attribute guard only permits exact ``object.__getattribute__``."""
    result = _scan_source(
        tmp_path,
        "concrete_int_getattribute_blocked.py",
        """
def target() -> int:
    method = int.__getattribute__
    return 100 // method(1, "real")
""",
    )

    assert not result.issues
    assert result.error is not None
    assert "__getattribute__" in str(result.error)


_OBJECT_GETATTRIBUTE_CATCHES_DESCRIPTOR_ATTRIBUTE_ERROR = """
class Slot:
    def __get__(self, instance, owner):
        instance.events.append("slot")
        raise AttributeError("denom")


class Box:
    denom = Slot()

    def __init__(self, left: int, right: int):
        self.left = left
        self.right = right
        self.events = []
        self.payload = [left + right]

    def __getattribute__(self, name: str):
        if name == "denom":
            events = object.__getattribute__(self, "events")
            events.append("ga")
            try:
                return object.__getattribute__(self, name)
            except AttributeError:
                payload = object.__getattribute__(self, "payload")
                payload.append(len(events))
                return object.__getattribute__(self, "fallback")
        return object.__getattribute__(self, name)
"""


def test_scan_file_getattribute_internal_attribute_error_fallback(
    tmp_path: Path,
) -> None:
    """Catching descriptor ``AttributeError`` inside ``__getattribute__`` keeps fallback effects."""
    result = _scan_source(
        tmp_path,
        "object_getattribute_caught_descriptor_bug.py",
        _OBJECT_GETATTRIBUTE_CATCHES_DESCRIPTOR_ATTRIBUTE_ERROR
        + """
    @property
    def fallback(self) -> int:
        left = object.__getattribute__(self, "left")
        right = object.__getattribute__(self, "right")
        if left == right:
            return left - right
        return left + right or 1


def target(a: int, b: int, c: int, d: int, e: int, f: int) -> int:
    box = Box(d, e)
    alias = box.payload
    for value in (a, b, c, f):
        if value >= 0:
            alias[0] = alias[0] + value
        else:
            alias[0] = alias[0] - value
    return 100 // box.denom + alias[-1]
""",
    )

    assert any(_issue_kind(issue) == "DIVISION_BY_ZERO" for issue in result.issues)
    assert not any(
        _issue_kind(issue) in {"ATTRIBUTE_ERROR", "TYPE_ERROR", "UNHANDLED_EXCEPTION"}
        for issue in result.issues
    )
    assert not result.degraded_passes


def test_scan_file_getattribute_internal_attribute_error_guarded_control(
    tmp_path: Path,
) -> None:
    """Fallback normalization must avoid a false division report."""
    result = _scan_source(
        tmp_path,
        "object_getattribute_caught_descriptor_guarded.py",
        _OBJECT_GETATTRIBUTE_CATCHES_DESCRIPTOR_ATTRIBUTE_ERROR
        + """
    @property
    def fallback(self) -> int:
        left = object.__getattribute__(self, "left")
        right = object.__getattribute__(self, "right")
        raw = left - right
        if raw == 0:
            return 1
        return raw


def target(a: int, b: int, c: int, d: int, e: int, f: int) -> int:
    box = Box(d, e)
    alias = box.payload
    for value in (a, b, c, f):
        if value >= 0:
            alias[0] = alias[0] + value
        else:
            alias[0] = alias[0] - value
    return 100 // box.denom + alias[-1]
""",
    )

    assert not any(
        _issue_kind(issue) in {"DIVISION_BY_ZERO", "ATTRIBUTE_ERROR", "TYPE_ERROR"}
        for issue in result.issues
    )
    assert not result.degraded_passes
