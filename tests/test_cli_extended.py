"""Tests for CLI commands (cli/commands.py, cli/scan.py, cli/scan_reporter.py)."""
from __future__ import annotations
import pytest
from unittest.mock import MagicMock, patch
from pysymex.cli.scan_reporter import ConsoleScanReporter
from pysymex.cli.scan import format_static_text_report, format_symbolic_text_report


class TestConsoleScanReporter:
    def test_creation(self):
        r = ConsoleScanReporter()
        assert r is not None

    def test_has_report_method(self):
        assert (hasattr(ConsoleScanReporter, 'report') or
                hasattr(ConsoleScanReporter, 'print_report') or
                hasattr(ConsoleScanReporter, 'format') or
                hasattr(ConsoleScanReporter, 'on_summary') or
                hasattr(ConsoleScanReporter, 'on_issue'))

    def test_report_empty(self):
        r = ConsoleScanReporter()
        if hasattr(r, 'report'):
            try:
                r.report([])
            except (TypeError, ValueError):
                pass


class TestFormatStaticTextReport:
    def test_callable(self):
        assert callable(format_static_text_report)

    def test_empty_issues(self):
        result = format_static_text_report([], total=0)
        assert isinstance(result, str)

    def test_with_suppressed(self):
        result = format_static_text_report([], total=5, suppressed=2)
        assert isinstance(result, str)


class TestFormatSymbolicTextReport:
    def test_callable(self):
        assert callable(format_symbolic_text_report)

    def test_empty_results(self):
        result = format_symbolic_text_report([], total=0, reproduce=False)
        assert isinstance(result, str)

    def test_with_reproduce(self):
        result = format_symbolic_text_report([], total=0, reproduce=True)
        assert isinstance(result, str)
