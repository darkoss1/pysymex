"""Tests for scanner CLI session accounting."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

from pysymex.scanner.cli import main
from pysymex.scanner.session import session_var
from pysymex.scanner.types import ScanResult, ScanSession


def _run_scanner_main(tmp_path: Path, scan_result_factory: object) -> ScanSession:
    target = tmp_path / "sample.py"
    target.write_text("x = 1\n", encoding="utf-8")
    log_path = tmp_path / "session.json"
    argv = ["pysymex.scanner", "--dir", str(tmp_path), "--log", str(log_path)]

    with (
        patch.object(sys, "argv", argv),
        patch("pysymex.scanner.cli.scan_directory", side_effect=scan_result_factory),
        patch("pysymex.scanner.cli.print_final_summary"),
    ):
        main()

    session = session_var.get()
    assert session is not None
    return session


def test_cli_does_not_duplicate_result_already_recorded_by_in_process_scan(tmp_path: Path) -> None:
    """Sequential scans already recorded through session_var must be added only once."""

    def scan_directory(*args: object, **kwargs: object) -> list[ScanResult]:
        _ = args
        _ = kwargs
        session = session_var.get()
        assert session is not None
        result = ScanResult(file_path=str(tmp_path / "sample.py"), timestamp="now")
        session.add_result(result)
        return [result]

    try:
        session = _run_scanner_main(tmp_path, scan_directory)
        assert len(session.results) == 1
    finally:
        session_var.set(None)


def test_cli_records_result_returned_without_in_process_session_write(tmp_path: Path) -> None:
    """Worker-returned results still need to be included in the parent session."""

    def scan_directory(*args: object, **kwargs: object) -> list[ScanResult]:
        _ = args
        _ = kwargs
        return [ScanResult(file_path=str(tmp_path / "sample.py"), timestamp="now")]

    try:
        session = _run_scanner_main(tmp_path, scan_directory)
        assert len(session.results) == 1
    finally:
        session_var.set(None)
