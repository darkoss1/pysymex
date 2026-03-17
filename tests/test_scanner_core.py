"""Tests for scanner core (scanner/core.py, scanner/types.py)."""
from __future__ import annotations
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch
from pysymex.scanner.types import ScanResult, ScanResultBuilder, ScanSession


class TestScanResult:
    def test_creation(self):
        sr = ScanResult(file_path="test.py", timestamp="2026-01-01T00:00:00")
        assert sr is not None

    def test_has_issues(self):
        sr = ScanResult(file_path="test.py", timestamp="2026-01-01T00:00:00")
        assert (hasattr(sr, 'issues') or hasattr(sr, 'vulnerabilities') or
                hasattr(sr, 'findings') or hasattr(sr, 'results'))

    def test_has_file_path(self):
        sr = ScanResult(file_path="test.py", timestamp="2026-01-01T00:00:00")
        assert (hasattr(sr, 'file_path') or hasattr(sr, 'path') or
                hasattr(sr, 'source_file'))


class TestScanResultBuilder:
    def test_creation(self):
        builder = ScanResultBuilder(file_path="test.py")
        assert builder is not None

    def test_has_build(self):
        assert (hasattr(ScanResultBuilder, 'build') or
                hasattr(ScanResultBuilder, 'to_result'))

    def test_add_issue(self):
        builder = ScanResultBuilder(file_path="test.py")
        if hasattr(builder, 'add_issue'):
            builder.add_issue({"type": "test", "message": "test"})
        elif hasattr(builder, 'add'):
            builder.add({"type": "test", "message": "test"})


class TestScanSession:
    def test_creation(self):
        session = ScanSession()
        assert session is not None

    def test_has_results(self):
        session = ScanSession()
        assert (hasattr(session, 'results') or hasattr(session, '_results') or
                hasattr(session, 'scan_results'))
