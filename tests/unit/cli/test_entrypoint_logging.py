from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

import pytest
from pytest import CaptureFixture

from pysymex._internal.cli.entrypoint import configure_cli_diagnostics
from pysymex._internal.logging.levels import LogLevel
from pysymex._internal.logging.root import get_logger, reset_logging


def _sandbox_startup_failure(stderr: str) -> bool:
    """Return True when a CLI subprocess failed before sandboxed code ran.

    Some CI kernels allow the sandbox tests to start; others deny Linux user
    namespace setup or run out of per-UID process slots under xdist.  Those
    failures happen before the verify command can exercise the serialization
    failure this test is about.
    """
    markers = (
        "unshare: fork failed",
        "Resource temporarily unavailable",
        "unshare: write failed /proc/self/uid_map",
        "Operation not permitted",
        "uid_map",
        "gid_map",
        "user namespace",
    )
    return any(marker in stderr for marker in markers)


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


def test_configure_cli_diagnostics_retargets_existing_child_loggers(
    capsys: CaptureFixture[str],
) -> None:
    """Module-level loggers created before CLI parsing must follow the configured stream."""
    reset_logging()
    logger = get_logger("pysymex.preconfigured")
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
    logger.warning("preconfigured warning")

    captured = capsys.readouterr()
    reset_logging()
    assert "preconfigured warning" not in captured.out
    assert "preconfigured warning" in captured.err


def test_verify_json_sandbox_serialization_failure_keeps_stdout_empty(
    tmp_path: Path,
) -> None:
    """Sandbox bridge diagnostics for JSON verify must not contaminate stdout."""
    target = tmp_path / "verify_box.py"
    target.write_text(
        dedent(
            """\
            class Box:
                def __init__(self, value: int) -> None:
                    self.value = value


            def target(x: int) -> int:
                return Box(x).value
            """
        ),
        encoding="utf-8",
    )

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pysymex",
            "contracts",
            str(target),
            "-f",
            "target",
            "--format",
            "json",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=45,
        check=False,
    )

    assert proc.returncode == 1
    assert proc.stdout == ""

    expected = "Function 'target' not found in sandbox module payload"
    if expected not in proc.stderr and _sandbox_startup_failure(proc.stderr):
        pytest.skip(f"sandbox unavailable in this environment: {proc.stderr}")
    assert expected in proc.stderr
