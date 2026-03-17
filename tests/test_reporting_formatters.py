"""Tests for reporting formatters (reporting/formatters.py)."""
from __future__ import annotations
import pytest
from pysymex.reporting.formatters import (
    Formatter,
    TextFormatter,
    JSONFormatter,
    HTMLFormatter,
    MarkdownFormatter,
    format_result,
)


class TestFormatter:
    def test_is_abstract(self):
        assert hasattr(Formatter, 'format')

    def test_cannot_instantiate(self):
        with pytest.raises(TypeError):
            Formatter()


class TestTextFormatter:
    def test_creation(self):
        f = TextFormatter()
        assert f is not None

    def test_has_format(self):
        f = TextFormatter()
        assert hasattr(f, 'format')

    def test_is_formatter(self):
        assert issubclass(TextFormatter, Formatter)


class TestJSONFormatter:
    def test_creation(self):
        f = JSONFormatter()
        assert f is not None

    def test_has_format(self):
        f = JSONFormatter()
        assert hasattr(f, 'format')

    def test_is_formatter(self):
        assert issubclass(JSONFormatter, Formatter)


class TestHTMLFormatter:
    def test_creation(self):
        f = HTMLFormatter()
        assert f is not None

    def test_is_formatter(self):
        assert issubclass(HTMLFormatter, Formatter)


class TestMarkdownFormatter:
    def test_creation(self):
        f = MarkdownFormatter()
        assert f is not None

    def test_is_formatter(self):
        assert issubclass(MarkdownFormatter, Formatter)


class TestFormatResult:
    def test_callable(self):
        assert callable(format_result)
