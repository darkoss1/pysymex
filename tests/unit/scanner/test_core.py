from __future__ import annotations

from pysymex.scanner.core import analyze_source, get_code_objects_with_context


def test_get_code_objects_with_context_tracks_nested_paths() -> None:
    src = """
class Outer:
    def method(self):
        def inner():
            return 1
        return inner()
"""
    root = compile(src, "sample.py", "exec")
    items = get_code_objects_with_context(root)
    full_paths = {full for _, _, full in items if full is not None}

    assert "Outer" in full_paths
    assert "Outer.method" in full_paths
    assert "Outer.method.inner" in full_paths


def test_analyze_source_reports_syntax_error() -> None:
    result = analyze_source("def broken(:\n    pass\n", "broken.py")
    assert result.error is not None
    assert "Syntax Error" in result.error

