"""Tests for the tracing analyzer package facade."""

from __future__ import annotations

import pysymex.tracing.analyzer as analyzer


def test_analyzer_package_keeps_pipeline_stream_and_cli_facades() -> None:
    """The package facade remains limited to analyzer workflows."""
    assert analyzer.FilterPipeline.__module__ == "pysymex.tracing.analyzer.pipeline.core"
    assert analyzer.SummaryAccumulator.__module__ == "pysymex.tracing.analyzer.stream_output"
    assert analyzer.build_parser.__module__ == "pysymex.tracing.analyzer.cli"
