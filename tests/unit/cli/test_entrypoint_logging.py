from __future__ import annotations

import argparse
from pathlib import Path

from pytest import CaptureFixture

from pysymex.cli.entrypoint import configure_cli_diagnostics
from pysymex.logger import LogLevel, get_logger, reset_logging


def test_configure_cli_diagnostics_sets_level_and_history() -> None:
    """CLI flags should configure the shared pysymex diagnostics state."""
    reset_logging()
    args = argparse.Namespace(
        quiet=False,
        diagnostic_trace=False,
        debug=True,
        verbose=False,
        format="text",
        log_category=["solver"],
        log_jsonl=None,
        log_history=2,
    )

    configure_cli_diagnostics(args)
    logger = get_logger("pysymex.test")
    logger.debug("kept", category="solver")
    logger.debug("filtered", category="opcode")

    assert logger.level == LogLevel.DEBUG
    assert [entry.message for entry in logger.get_entries()] == ["kept"]


def test_configure_cli_diagnostics_writes_jsonl(tmp_path: Path) -> None:
    """CLI JSONL diagnostics should use the structured event sink."""
    reset_logging()
    jsonl_path = tmp_path / "diag.jsonl"
    args = argparse.Namespace(
        quiet=False,
        diagnostic_trace=False,
        debug=True,
        verbose=False,
        format="text",
        log_category=None,
        log_jsonl=str(jsonl_path),
        log_history=0,
    )

    configure_cli_diagnostics(args)
    get_logger("pysymex.test").debug("json event")

    assert '"message":"json event"' in jsonl_path.read_text(encoding="utf-8")


def test_configure_cli_diagnostics_routes_structured_format_logs_to_stderr(
    capsys: CaptureFixture[str],
) -> None:
    """Machine-readable stdout should not be prefixed with diagnostics."""
    reset_logging()
    args = argparse.Namespace(
        quiet=False,
        diagnostic_trace=False,
        debug=False,
        verbose=False,
        format="json",
        log_category=None,
        log_jsonl=None,
        log_history=0,
    )

    configure_cli_diagnostics(args)
    get_logger("pysymex.test").warning("json warning")

    captured = capsys.readouterr()
    reset_logging()
    assert "json warning" not in captured.out
    assert "json warning" in captured.err
