from unittest.mock import MagicMock

import pysymex._internal.cli.reporter
from pysymex._internal.scanner.types import ScanResult


class TestConsoleScanReporter:
    """Test suite for pysymex._internal.cli.reporter.ConsoleScanReporter."""

    def test_on_file_start(self) -> None:
        """Test on_file_start behavior."""
        reporter = pysymex._internal.cli.reporter.ConsoleScanReporter()
        reporter.on_file_start("test.py")

    def test_on_file_done(self) -> None:
        """Test on_file_done behavior."""
        reporter = pysymex._internal.cli.reporter.ConsoleScanReporter()
        mock_result = MagicMock(spec=ScanResult)
        mock_result.issues = []
        mock_result.error = None
        mock_result.code_objects = 1
        mock_result.paths_explored = 1
        reporter.on_file_done("test.py", mock_result)

    def test_on_issue(self) -> None:
        """Test on_issue behavior."""
        reporter = pysymex._internal.cli.reporter.ConsoleScanReporter()
        reporter.on_issue({"kind": "TEST", "message": "msg", "line": 1})

    def test_on_error(self) -> None:
        """Test on_error behavior."""
        reporter = pysymex._internal.cli.reporter.ConsoleScanReporter()
        reporter.on_error("test.py", "error msg")

    def test_on_progress(self) -> None:
        """Test on_progress behavior."""
        reporter = pysymex._internal.cli.reporter.ConsoleScanReporter()
        mock_result = MagicMock(spec=ScanResult)
        mock_result.issues = []
        mock_result.error = None
        reporter.on_progress(1, 10, "test.py", mock_result)

    def test_on_status(self) -> None:
        """Test on_status behavior."""
        reporter = pysymex._internal.cli.reporter.ConsoleScanReporter()
        reporter.on_status("status message")

    def test_on_summary(self) -> None:
        """Test on_summary behavior."""
        reporter = pysymex._internal.cli.reporter.ConsoleScanReporter()
        reporter.on_summary([], 0)
