"""Tests for pysymex.tracing.analyzer.manual — print_ai_manual."""

from __future__ import annotations

import io
from unittest.mock import MagicMock, patch

from pysymex.tracing.analyzer.manual import print_ai_manual


def test_print_ai_manual_prints_documentation() -> None:
    """print_ai_manual writes documentation to stdout buffer."""
    mock_stdout = MagicMock()
    mock_stdout.buffer = io.BytesIO()
    with patch("sys.stdout", mock_stdout):
        print_ai_manual()
    output = mock_stdout.buffer.getvalue().decode("utf-8")
    assert "pysymex Trace Analyzer" in output
    assert "LLM Diagnostic Manual" in output
