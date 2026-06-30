"""Scanner regressions for runtime class-attribute descriptor binding."""

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


def _issue_message(issue: object) -> str:
    if isinstance(issue, dict):
        return str(cast("Mapping[str, object]", issue).get("message", ""))
    return str(getattr(issue, "message", ""))


def _scan_source(tmp_path: Path, filename: str, source: str):
    target = tmp_path / filename
    target.write_text(source, encoding="utf-8")
    return scan_file(
        target,
        max_paths=360,
        timeout=8,
        use_sandbox=False,
        no_cache=True,
        max_iterations=10000,
    )


_ATTACH_MARKER = """
def attach_marker(cls):
    class Marker:
        def __get__(self, instance, owner):
            if instance is None:
                return self
            return instance.payload

    original = cls.flip

    def wrapped(self, amount: int) -> int:
        value = original(self, amount)
        self.payload = value
        return value

    cls.marker = Marker()
    cls.flip = wrapped
    return cls
"""


_BOX_WITH_META = """
    class Meta(type):
        def __call__(cls, seed: int, guard: int):
            item = super().__call__()
            item.payload = seed
            item.guard = guard
            return item

    @attach_marker
    class Box(metaclass=Meta):
        def flip(self, amount: int) -> int:
            current = self.payload
            if amount > 0:
                current -= amount
            else:
                current += amount
            return current

        @property
        def denom(self) -> int:
            return self.marker
"""


def test_scan_file_class_decorator_rebound_method_keeps_descriptor_binding(
    tmp_path: Path,
) -> None:
    """A class decorator assigning a function keeps instance-method binding."""
    result = _scan_source(
        tmp_path,
        "class_decorator_rebound_method.py",
        _ATTACH_MARKER
        + """
def target(a: int, b: int, c: int, d: int, e: int) -> int:
"""
        + _BOX_WITH_META
        + """
    box = Box(a + b, c)
    branch_total = 0
    if a > 0:
        branch_total += 1
    else:
        branch_total -= 1
    if b > 0:
        branch_total += 1
    else:
        branch_total -= 1
    if c >= 0:
        branch_total += 1
    else:
        branch_total -= 1
    if d == branch_total:
        box.flip(e)
    else:
        box.flip(-e)
    return 100 // box.denom
""",
    )

    assert any(_issue_kind(issue) == "DIVISION_BY_ZERO" for issue in result.issues)
    assert not any(
        _issue_kind(issue) == "TYPE_ERROR"
        and "wrapped() missing required argument" in _issue_message(issue)
        for issue in result.issues
    )


def test_scan_file_class_decorator_rebound_method_no_false_positive(
    tmp_path: Path,
) -> None:
    """A guarded rebinding path must not invent division or binding errors."""
    result = _scan_source(
        tmp_path,
        "class_decorator_rebound_method_guarded.py",
        _ATTACH_MARKER
        + """
def target(a: int, b: int, c: int, d: int, e: int) -> int:
"""
        + _BOX_WITH_META
        + """
    box = Box(a + b, c)
    if a > b:
        box.flip(e)
    else:
        box.flip(-e)
    if box.denom == 0:
        denom = 1
    else:
        denom = box.denom
    return 100 // denom
""",
    )

    assert not any(
        _issue_kind(issue) in {"DIVISION_BY_ZERO", "TYPE_ERROR"} for issue in result.issues
    )


def test_scan_file_builtin_setattr_rebound_class_method(
    tmp_path: Path,
) -> None:
    """``setattr(cls, name, func)`` shares ordinary class-write method binding."""
    result = _scan_source(
        tmp_path,
        "builtin_setattr_rebound_method.py",
        """
def target(a: int, b: int, e: int) -> int:
    class Box:
        def __init__(self, seed: int):
            self.payload = seed

        def flip(self, amount: int) -> int:
            current = self.payload
            if amount > 0:
                current -= amount
            else:
                current += amount
            return current

    original = Box.flip

    def wrapped(self, amount: int) -> int:
        value = original(self, amount)
        self.payload = value
        return value

    setattr(Box, "flip", wrapped)
    box = Box(a + b)
    box.flip(e)
    return 100 // box.payload
""",
    )

    assert any(_issue_kind(issue) == "DIVISION_BY_ZERO" for issue in result.issues)
    assert not any(_issue_kind(issue) == "ATTRIBUTE_ERROR" for issue in result.issues)


def test_scan_file_runtime_classmethod_class_access_keeps_class_binding(
    tmp_path: Path,
) -> None:
    """Runtime ``classmethod(function)`` writes bind the class for class access."""
    result = _scan_source(
        tmp_path,
        "runtime_classmethod_class_access.py",
        """
def target(a: int, b: int) -> int:
    class Box:
        base = 0

    def helper(cls, value: int) -> int:
        return value + cls.base

    Box.pick = classmethod(helper)
    return 10 // Box.pick(a - b)
""",
    )

    assert any(_issue_kind(issue) == "DIVISION_BY_ZERO" for issue in result.issues)
    assert not any(_issue_kind(issue) == "TYPE_ERROR" for issue in result.issues)


def test_scan_file_runtime_classmethod_class_access_no_false_positive(
    tmp_path: Path,
) -> None:
    """Guarded runtime ``classmethod(function)`` writes do not invent TypeError."""
    result = _scan_source(
        tmp_path,
        "runtime_classmethod_class_access_guarded.py",
        """
def target(a: int, b: int) -> int:
    class Box:
        base = 0

    def helper(cls, value: int) -> int:
        return value + cls.base

    Box.pick = classmethod(helper)
    denom = Box.pick(a - b)
    if denom == 0:
        denom = 1
    return 10 // denom
""",
    )

    assert not any(
        _issue_kind(issue) in {"DIVISION_BY_ZERO", "TYPE_ERROR"} for issue in result.issues
    )


def test_scan_file_runtime_staticmethod_instance_access_keeps_static_binding(
    tmp_path: Path,
) -> None:
    """Runtime ``staticmethod(function)`` writes do not bind an instance receiver."""
    result = _scan_source(
        tmp_path,
        "runtime_staticmethod_instance_access.py",
        """
def target(a: int, b: int) -> int:
    class Box:
        pass

    def helper(value: int) -> int:
        return value

    Box.pick = staticmethod(helper)
    box = Box()
    return 10 // box.pick(a - b)
""",
    )

    assert any(_issue_kind(issue) == "DIVISION_BY_ZERO" for issue in result.issues)
    assert not any(_issue_kind(issue) == "TYPE_ERROR" for issue in result.issues)


def test_scan_file_runtime_staticmethod_instance_access_no_false_positive(
    tmp_path: Path,
) -> None:
    """Guarded runtime ``staticmethod(function)`` writes do not invent TypeError."""
    result = _scan_source(
        tmp_path,
        "runtime_staticmethod_instance_access_guarded.py",
        """
def target(a: int, b: int) -> int:
    class Box:
        pass

    def helper(value: int) -> int:
        return value

    Box.pick = staticmethod(helper)
    box = Box()
    denom = box.pick(a - b)
    if denom == 0:
        denom = 1
    return 10 // denom
""",
    )

    assert not any(
        _issue_kind(issue) in {"DIVISION_BY_ZERO", "TYPE_ERROR"} for issue in result.issues
    )


def test_scan_file_builtin_setattr_dynamic_descriptor(
    tmp_path: Path,
) -> None:
    """``setattr(cls, name, descriptor)`` shares dynamic descriptor retention."""
    result = _scan_source(
        tmp_path,
        "builtin_setattr_dynamic_descriptor.py",
        """
def target(a: int, b: int, e: int) -> int:
    class Box:
        def __init__(self, seed: int):
            self.payload = seed

        def flip(self, amount: int) -> int:
            current = self.payload
            if amount > 0:
                current -= amount
            else:
                current += amount
            self.payload = current
            return current

    class Marker:
        def __get__(self, instance, owner):
            if instance is None:
                return self
            return instance.payload

    setattr(Box, "marker", Marker())
    box = Box(a + b)
    box.flip(e)
    return 100 // box.marker
""",
    )

    assert any(_issue_kind(issue) == "DIVISION_BY_ZERO" for issue in result.issues)
    assert not any(_issue_kind(issue) == "ATTRIBUTE_ERROR" for issue in result.issues)
