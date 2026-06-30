"""Tests for pysymex._internal.cli.output helper functions."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from pysymex._internal.cli.output import CliOutput


def test_format_cli_error_prefix() -> None:
    """CliOutput.error_line should always include the standardized CLI error prefix."""
    rendered = CliOutput.error_line("problem")
    assert rendered.startswith("Error: ")


def test_print_cli_error_writes_to_provided_stream() -> None:
    """CliOutput.error should emit the standardized error line to the provided stream."""
    stream = io.StringIO()
    CliOutput.error("problem", stream=stream)
    assert stream.getvalue().strip() == "Error: problem"


def test_format_cli_warning_prefix() -> None:
    """CliOutput.warning_line should always include the standardized warning prefix."""
    rendered = CliOutput.warning_line("heads up")
    assert rendered.startswith("Warning: ")


def test_print_cli_warning_writes_to_provided_stream() -> None:
    """CliOutput.warning should emit the standardized warning line to the provided stream."""
    stream = io.StringIO()
    CliOutput.warning("heads up", stream=stream)
    assert stream.getvalue().strip() == "Warning: heads up"


def test_print_cli_warning_does_not_duplicate_normal_stderr(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """CliOutput.warning should not also emit a logger-formatted warning line."""
    CliOutput.warning("heads up")
    captured = capsys.readouterr()
    assert captured.err.splitlines() == ["Warning: heads up"]


def test_format_progress_line_uses_progress_prefix() -> None:
    """CliOutput.progress_line should emit the standardized progress prefix."""
    rendered = CliOutput.progress_line(2, 4, "demo.py", "[OK]")
    assert rendered.startswith("Progress: ")


def test_emit_cli_output_writes_output_file(tmp_path: Path) -> None:
    """CliOutput.emit should write the full report content to the target file path."""
    output_path = tmp_path / "test_cli_output.txt"
    CliOutput.emit("report-body", output_path=str(output_path), verbose=False)
    assert output_path.read_text(encoding="utf-8") == "report-body"
