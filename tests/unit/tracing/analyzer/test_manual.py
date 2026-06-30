"""Tests for pysymex._internal.tracing.analyzer.manual content ownership."""

from __future__ import annotations

from pysymex._internal.tracing.analyzer.manual.text.content import AI_MANUAL


def test_ai_manual_exposes_documentation_text_without_stdout_side_effect() -> None:
    assert "pysymex Trace Analyzer" in AI_MANUAL
    assert "LLM Diagnostic Manual" in AI_MANUAL
