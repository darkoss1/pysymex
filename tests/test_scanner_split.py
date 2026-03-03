"""Tests for the scanner module (scan_file, scan_directory, ScanResult, ScanSession).

Targets the split modules:
  - pysymex.scanner.types (ScanResult, ScanSession)
  - pysymex.scanner.core (scan_file, scan_directory, analyze_file, etc.)
  - pysymex.scanner (hub re-exports)

These modules had no proper pytest coverage prior to this file.
"""

from __future__ import annotations


import json

import os

import tempfile

import textwrap


import pytest


from pysymex.scanner import (
    ScanResult,
    ScanSession,
    scan_file,
    scan_directory,
    analyze_file,
    get_code_objects_with_context,
)


class TestScanResult:
    def test_construction(self):
        r = ScanResult(file_path="test.py", timestamp="2026-01-01T00:00:00")

        assert r.file_path == "test.py"

        assert r.timestamp == "2026-01-01T00:00:00"

        assert r.issues == []

        assert r.code_objects == 0

        assert r.paths_explored == 0

        assert r.error is None

    def test_with_issues(self):
        issues = [{"type": "unbound_variable", "line": 5}]

        r = ScanResult(
            file_path="buggy.py",
            timestamp="2026-02-28",
            issues=issues,
            code_objects=3,
            paths_explored=10,
        )

        assert len(r.issues) == 1

        assert r.code_objects == 3

        assert r.paths_explored == 10

    def test_with_error(self):
        r = ScanResult(
            file_path="bad.py",
            timestamp="2026-01-01",
            error="SyntaxError",
        )

        assert r.error == "SyntaxError"

    def test_to_dict(self):
        r = ScanResult(file_path="test.py", timestamp="2026-01-01")

        d = r.to_dict()

        assert isinstance(d, dict)

        assert d["file"] == "test.py"

        assert d["timestamp"] == "2026-01-01"


class TestScanSession:
    def test_construction(self):
        session = ScanSession()

        assert session is not None

    def test_add_result_and_summary(self, tmp_path):
        session = ScanSession(log_file=tmp_path / "log.json")

        r = ScanResult(file_path="a.py", timestamp="2026-01-01", code_objects=2)

        session.add_result(r)

        summary = session.get_summary()

        assert isinstance(summary, dict)

        assert summary.get("files_scanned", 0) >= 1

    def test_multiple_results(self, tmp_path):
        session = ScanSession(log_file=tmp_path / "log.json")

        for i in range(5):
            session.add_result(ScanResult(file_path=f"file{i}.py", timestamp="2026-01-01"))

        summary = session.get_summary()

        assert summary.get("files_scanned", 0) >= 5


class TestGetCodeObjectsWithContext:
    def test_simple_module(self):
        code = compile("x = 1\ny = 2", "<test>", "exec")

        result = get_code_objects_with_context(code)

        assert isinstance(result, list)

        assert len(result) >= 1

    def test_module_with_function(self):
        source = textwrap.dedent("""\
            def foo():
                return 42

            def bar(x):
                return x + 1
        """)

        code = compile(source, "<test>", "exec")

        result = get_code_objects_with_context(code)

        assert len(result) >= 2

    def test_nested_functions(self):
        source = textwrap.dedent("""\
            def outer():
                def inner():
                    return 1
                return inner()
        """)

        code = compile(source, "<test>", "exec")

        result = get_code_objects_with_context(code)

        assert len(result) >= 2


class TestScanFile:
    def test_scan_clean_file(self):
        """Scanning a simple clean file should return a ScanResult."""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write("x = 42\n")

            f.flush()

            path = f.name

        try:
            result = scan_file(path, max_paths=50, timeout=10.0)

            assert isinstance(result, ScanResult)

            assert result.file_path == path

            assert result.error is None

        finally:
            os.unlink(path)

    def test_scan_file_with_function(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write(textwrap.dedent("""\
                def add(a, b):
                    return a + b

                result = add(1, 2)
            """))

            f.flush()

            path = f.name

        try:
            result = scan_file(path, max_paths=50, timeout=10.0)

            assert isinstance(result, ScanResult)

            assert result.code_objects >= 1

        finally:
            os.unlink(path)

    def test_scan_nonexistent_file(self):
        """Scanning a nonexistent file should return an error result, not crash."""

        result = scan_file("/nonexistent/path.py", max_paths=10, timeout=5.0)

        assert isinstance(result, ScanResult)

        assert result.error is not None

    def test_scan_syntax_error_file(self):
        """Scanning a file with syntax errors should handle gracefully."""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write("def broken(\n")

            f.flush()

            path = f.name

        try:
            result = scan_file(path, max_paths=10, timeout=5.0)

            assert isinstance(result, ScanResult)

            assert result.error is not None

        finally:
            os.unlink(path)


class TestAnalyzeFile:
    def test_analyze_simple_file(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write("x = 42\n")

            f.flush()

            path = f.name

        try:
            from pathlib import Path

            result = analyze_file(Path(path))

            assert isinstance(result, ScanResult)

        finally:
            os.unlink(path)


class TestScanDirectory:
    def test_scan_temp_directory(self):
        """Scan a directory with a few Python files."""

        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(3):
                path = os.path.join(tmpdir, f"file{i}.py")

                with open(path, "w", encoding="utf-8") as f:
                    f.write(f"value = {i}\n")

            results = scan_directory(tmpdir, verbose=False, max_paths=20, timeout=10.0, workers=1)

            assert isinstance(results, list)

            assert len(results) == 3

            for r in results:
                assert isinstance(r, ScanResult)

    def test_scan_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            results = scan_directory(tmpdir, verbose=False, max_paths=10, timeout=5.0)

            assert isinstance(results, list)

            assert len(results) == 0


class TestScannerHub:
    def test_types_accessible(self):
        from pysymex.scanner import ScanResult, ScanSession

        assert ScanResult is not None

        assert ScanSession is not None

    def test_core_accessible(self):
        from pysymex.scanner import (
            scan_file,
            scan_directory,
            analyze_file,
            get_code_objects_with_context,
        )

        assert all(
            c is not None
            for c in [
                scan_file,
                scan_directory,
                analyze_file,
                get_code_objects_with_context,
            ]
        )

    def test_identity(self):
        from pysymex.scanner.types import ScanResult as T1

        from pysymex.scanner import ScanResult as T2

        assert T1 is T2

        from pysymex.scanner.core import scan_file as C1

        from pysymex.scanner import scan_file as C2

        assert C1 is C2
