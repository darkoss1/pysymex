"""Tests for scanner cli entrypoint."""

from __future__ import annotations

import subprocess
import sys


class TestScannerMain:
    """Test class for the scanner __main__ execution."""

    def test_scanner_main_execution(self) -> None:
        """Verify running pysymex.scanner as a module invokes main successfully."""
        result = subprocess.run(
            [sys.executable, "-m", "pysymex.scanner", "-h"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "usage:" in result.stdout.lower()
        assert "pysymex" in result.stdout.lower()
