"""Tests for pysymex.cli.output helper functions."""

from __future__ import annotations

import io
from pathlib import Path

from pysymex.cli.output import (
    emit_cli_output,
    format_cli_error,
    format_cli_warning,
    format_progress_line,
    print_cli_error,
    print_cli_warning,
)


def test_format_cli_error_prefix() -> None:
    """format_cli_error should always include the standardized CLI error prefix."""
    rendered = format_cli_error("problem")
    assert rendered.startswith("[X] Error: ")


def test_print_cli_error_writes_to_provided_stream() -> None:
    """print_cli_error should emit the standardized error line to the provided stream."""
    stream = io.StringIO()
    print_cli_error("problem", stream=stream)
    assert stream.getvalue().strip() == "[X] Error: problem"


def test_format_cli_warning_prefix() -> None:
    """format_cli_warning should always include the standardized warning prefix."""
    rendered = format_cli_warning("heads up")
    assert rendered.startswith("[WARN] ")


def test_print_cli_warning_writes_to_provided_stream() -> None:
    """print_cli_warning should emit the standardized warning line to the provided stream."""
    stream = io.StringIO()
    print_cli_warning("heads up", stream=stream)
    assert stream.getvalue().strip() == "[WARN] heads up"


def test_format_progress_line_uses_progress_prefix() -> None:
    """format_progress_line should emit the standardized progress prefix."""
    rendered = format_progress_line(2, 4, "demo.py", "[OK]")
    assert rendered.startswith("[PROGRESS] ")


def test_emit_cli_output_writes_output_file(tmp_path: Path) -> None:
    """emit_cli_output should write the full report content to the target file path."""
    output_path = tmp_path / "test_cli_output.txt"
    emit_cli_output("report-body", output_path=str(output_path), verbose=False)
    assert output_path.read_text(encoding="utf-8") == "report-body"
