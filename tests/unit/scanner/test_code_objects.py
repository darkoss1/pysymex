"""Tests for static code-object discovery."""

from __future__ import annotations

from pysymex._internal.scanner.code import get_code_objects_with_context


def test_get_code_objects_includes_module_code_with_no_parent_path() -> None:
    """Module code has no parent path."""
    code = compile("x = 1", "<test>", "exec")
    items = get_code_objects_with_context(code)
    assert len(items) >= 1
    _, parent, full_path = items[0]
    assert parent is None
    assert full_path is None


def test_get_code_objects_records_nested_function_paths() -> None:
    """Nested functions have dotted paths."""
    src = """
def outer():
    def inner():
        return 1
    return inner()
"""
    code = compile(src, "<test>", "exec")
    items = get_code_objects_with_context(code)
    paths = {full for _, _, full in items if full is not None}
    assert "outer" in paths
    assert "outer.inner" in paths


def test_get_code_objects_records_nested_class_method_paths() -> None:
    """Nested classes and methods have dotted paths."""
    src = """
class Outer:
    def method(self):
        def inner():
            return 1
        return inner()
"""
    code = compile(src, "<test>", "exec")
    items = get_code_objects_with_context(code)
    paths = {full for _, _, full in items if full is not None}
    assert "Outer" in paths
    assert "Outer.method" in paths
    assert "Outer.method.inner" in paths
