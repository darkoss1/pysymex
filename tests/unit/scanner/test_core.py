"""Tests for pysymex.scanner.core — source analysis and scanning helpers."""

from __future__ import annotations

import types

from pysymex.scanner.core import (
    _auto_worker_count,
    _build_symbolic_vars,
    _descending_issue_count,
    _is_object_dict,
    analyze_source,
    get_code_objects_with_context,
)


class TestDescendingIssueCount:
    """Tests for _descending_issue_count sort key."""

    def test_returns_negative(self) -> None:
        """Returns negated count for descending sort."""
        assert _descending_issue_count(("file.py", 5)) == -5

    def test_zero(self) -> None:
        """Zero count returns zero."""
        assert _descending_issue_count(("file.py", 0)) == 0


class TestBuildSymbolicVars:
    """Tests for _build_symbolic_vars parameter inference."""

    def test_simple_function(self) -> None:
        """Simple function parameters become 'int'."""
        code = compile("def f(x, y): return x + y", "<test>", "exec")
        inner = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        result = _build_symbolic_vars(inner, include_collection_heuristics=False)
        assert result == {"x": "int", "y": "int"}

    def test_self_becomes_object(self) -> None:
        """'self' parameter becomes 'object'."""
        code = compile("class C:\n def m(self, x): pass\n", "<test>", "exec")
        # Navigate to method code
        class_code = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        method_code = [c for c in class_code.co_consts if hasattr(c, "co_code")][0]
        result = _build_symbolic_vars(method_code, include_collection_heuristics=False)
        assert result["self"] == "object"

    def test_cls_becomes_object(self) -> None:
        """'cls' parameter becomes 'object'."""
        code = compile("class C:\n @classmethod\n def m(cls, x): pass\n", "<test>", "exec")
        class_code = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        method_code = [c for c in class_code.co_consts if hasattr(c, "co_code")][0]
        result = _build_symbolic_vars(method_code, include_collection_heuristics=False)
        assert result["cls"] == "object"

    def test_collection_heuristics_list(self) -> None:
        """Parameter containing 'list' becomes 'list' with heuristics."""
        code = compile("def f(items): pass", "<test>", "exec")
        inner = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        result = _build_symbolic_vars(inner, include_collection_heuristics=True)
        assert result["items"] == "list"

    def test_collection_heuristics_dict(self) -> None:
        """Parameter containing 'config' becomes 'dict' with heuristics."""
        code = compile("def f(config): pass", "<test>", "exec")
        inner = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        result = _build_symbolic_vars(inner, include_collection_heuristics=True)
        assert result["config"] == "dict"

    def test_no_heuristics_fallback(self) -> None:
        """Without heuristics, 'items' becomes 'int'."""
        code = compile("def f(items): pass", "<test>", "exec")
        inner = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        result = _build_symbolic_vars(inner, include_collection_heuristics=False)
        assert result["items"] == "int"

    def test_no_args(self) -> None:
        """Function with no args returns empty dict."""
        code = compile("def f(): pass", "<test>", "exec")
        inner = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        result = _build_symbolic_vars(inner, include_collection_heuristics=False)
        assert result == {}


class TestIsObjectDict:
    """Tests for _is_object_dict TypeGuard."""

    def test_dict_returns_true(self) -> None:
        """Dict passes."""
        assert _is_object_dict({"a": 1}) is True

    def test_list_returns_false(self) -> None:
        """List fails."""
        assert _is_object_dict([1]) is False


class TestAutoWorkerCount:
    """Tests for _auto_worker_count."""

    def test_without_sandbox(self) -> None:
        """Without sandbox, cap is 4."""
        count = _auto_worker_count(use_sandbox=False)
        assert 1 <= count <= 4

    def test_with_sandbox(self) -> None:
        """With sandbox, cap is 2."""
        count = _auto_worker_count(use_sandbox=True)
        assert 1 <= count <= 2


class TestGetCodeObjectsWithContext:
    """Tests for get_code_objects_with_context."""

    def test_module_level(self) -> None:
        """Module code has None path."""
        code = compile("x = 1", "<test>", "exec")
        items = get_code_objects_with_context(code)
        assert len(items) >= 1
        _, parent, full_path = items[0]
        assert parent is None
        assert full_path is None

    def test_nested_functions(self) -> None:
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

    def test_nested_classes(self) -> None:
        """Nested classes have dotted paths."""
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


class TestAnalyzeSource:
    """Tests for analyze_source core analysis."""

    def test_syntax_error(self) -> None:
        """Syntax error is reported."""
        result = analyze_source("def broken(:\n    pass\n", "broken.py")
        assert result.error is not None
        assert "Syntax Error" in result.error

    def test_valid_source(self) -> None:
        """Valid source produces a ScanResult."""
        result = analyze_source("x = 1\ny = 2\n", "test.py")
        assert result.file_path == "test.py"
        assert result.error is None or result.error == ""

    def test_empty_source(self) -> None:
        """Empty source does not crash."""
        result = analyze_source("", "empty.py")
        assert result.file_path == "empty.py"
