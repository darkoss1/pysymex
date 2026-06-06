from pathlib import Path
from unittest.mock import MagicMock

import pytest

import pysymex.cli.reporter
from pysymex.scanner.types import ScanResult, ScanSession


class TestConsoleScanReporter:
    """Test suite for pysymex.cli.reporter.ConsoleScanReporter."""

    def test_on_file_start(self) -> None:
        """Test on_file_start behavior."""
        reporter = pysymex.cli.reporter.ConsoleScanReporter()
        reporter.on_file_start("test.py")

    def test_on_file_done(self) -> None:
        """Test on_file_done behavior."""
        reporter = pysymex.cli.reporter.ConsoleScanReporter()
        mock_result = MagicMock(spec=ScanResult)
        mock_result.issues = []
        mock_result.error = None
        mock_result.code_objects = 1
        mock_result.paths_explored = 1
        reporter.on_file_done("test.py", mock_result)

    def test_on_issue(self) -> None:
        """Test on_issue behavior."""
        reporter = pysymex.cli.reporter.ConsoleScanReporter()
        reporter.on_issue({"kind": "TEST", "message": "msg", "line": 1})

    def test_on_error(self) -> None:
        """Test on_error behavior."""
        reporter = pysymex.cli.reporter.ConsoleScanReporter()
        reporter.on_error("test.py", "error msg")

    def test_on_progress(self) -> None:
        """Test on_progress behavior."""
        reporter = pysymex.cli.reporter.ConsoleScanReporter()
        mock_result = MagicMock(spec=ScanResult)
        mock_result.issues = []
        mock_result.error = None
        reporter.on_progress(1, 10, "test.py", mock_result)

    def test_on_status(self) -> None:
        """Test on_status behavior."""
        reporter = pysymex.cli.reporter.ConsoleScanReporter()
        reporter.on_status("status message")

    def test_on_summary(self) -> None:
        """Test on_summary behavior."""
        reporter = pysymex.cli.reporter.ConsoleScanReporter()
        reporter.on_summary([], 0)

    def test_on_session_summary(self) -> None:
        """Test on_session_summary behavior."""
        reporter = pysymex.cli.reporter.ConsoleScanReporter()
        mock_session = MagicMock(spec=ScanSession)
        mock_session.get_summary.return_value = {
            "files_scanned": 1,
            "files_with_issues": 0,
            "files_clean": 1,
            "files_error": 0,
            "files_degraded": 0,
            "total_issues": 0,
            "issue_breakdown": {},
        }
        mock_session.log_file = "log.txt"
        mock_session.log_write_error = None
        reporter.on_session_summary(mock_session)

    def test_on_session_summary_reports_log_write_failure(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        reporter = pysymex.cli.reporter.ConsoleScanReporter()
        session = ScanSession(log_file=tmp_path / "scan.json")
        session.log_write_error = "PermissionError(denied)"

        reporter.on_session_summary(session)

        output = capsys.readouterr().out
        assert "Log not saved to" in output
        assert "Log saved to" not in output
