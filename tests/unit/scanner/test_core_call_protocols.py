from __future__ import annotations

from pathlib import Path

import pytest

from pysymex.scanner.file import scan_file


def test_scan_file_respects_callable_instance_guard(tmp_path: Path) -> None:
    target = tmp_path / "callable_instance_guard.py"
    target.write_text(
        "class Guard:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __call__(self) -> bool:\n"
        "        return self.value != 0\n\n"
        "def target(value: int) -> int:\n"
        "    guard = Guard(value)\n"
        "    if guard():\n"
        "        return 1 // value\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("line") == 11
        for issue in result.issues
    )


def test_scan_file_preserves_callable_instance_false_bug_path(tmp_path: Path) -> None:
    target = tmp_path / "callable_instance_false_path.py"
    target.write_text(
        "class Guard:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __call__(self) -> bool:\n"
        "        return self.value != 0\n\n"
        "def target(value: int) -> int:\n"
        "    guard = Guard(value)\n"
        "    if not guard():\n"
        "        return 1 // value\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("line") == 11
        for issue in result.issues
    )


def test_scan_file_passes_same_instance_to_callable_protocol(tmp_path: Path) -> None:
    target = tmp_path / "callable_instance_same_argument.py"
    target.write_text(
        "class Guard:\n"
        "    def __call__(self, value: object) -> bool:\n"
        "        return True\n\n"
        "def target(value: int) -> int:\n"
        "    guard = Guard()\n"
        "    if guard(guard):\n"
        "        return 1 // value\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


@pytest.mark.parametrize(
    ("filename", "source"),
    [
        (
            "bound_method_default.py",
            "class Box:\n"
            "    def value(self, x: int = 2) -> int:\n"
            "        return x + 1\n\n"
            "result = Box().value()\n",
        ),
        (
            "callable_instance_default.py",
            "class Adder:\n"
            "    def __call__(self, x: int = 2) -> int:\n"
            "        return x + 1\n\n"
            "result = Adder()()\n",
        ),
        (
            "classmethod_default.py",
            "class Box:\n"
            "    @classmethod\n"
            "    def value(cls, x: int = 2) -> int:\n"
            "        return x + 1\n\n"
            "result = Box.value()\n",
        ),
        (
            "staticmethod_default.py",
            "class Box:\n"
            "    @staticmethod\n"
            "    def value(x: int = 2) -> int:\n"
            "        return x + 1\n\n"
            "result = Box.value()\n",
        ),
    ],
)
def test_scan_file_preserves_class_body_method_defaults(
    tmp_path: Path,
    filename: str,
    source: str,
) -> None:
    target = tmp_path / filename
    target.write_text(source, encoding="utf-8")

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)


def test_scan_file_classmethod_preserves_class_receiver_for_staticmethod_lookup(
    tmp_path: Path,
) -> None:
    target = tmp_path / "classmethod_staticmethod_binding.py"
    target.write_text(
        "def target() -> int:\n"
        "    class Box:\n"
        "        @staticmethod\n"
        "        def static(item: int) -> int:\n"
        "            return item + 1\n\n"
        "        @classmethod\n"
        "        def make(cls, item: int) -> int:\n"
        "            return cls.static(item)\n\n"
        "    x = 1\n"
        "    return Box.make(x)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    forbidden_kinds = {"ATTRIBUTE_ERROR", "TYPE_ERROR"}
    assert not any(issue.get("kind") in forbidden_kinds for issue in result.issues)
