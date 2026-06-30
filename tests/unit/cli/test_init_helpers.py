"""Tests for pysymex._internal.cli helper functions."""

from __future__ import annotations

from pysymex._internal.cli.entry import normalize_argv


class TestCliHelpers:
    """Test suite for pysymex._internal.cli helper functions."""

    def test_normalize_argv_with_subcommand(self) -> None:
        """Test that normalize_argv passes through when subcommand is present."""
        argv = ["contracts", "file.py", "-f", "func"]
        result = normalize_argv(argv)
        assert result == argv

    def test_normalize_argv_without_function_flag(self) -> None:
        """Test that normalize_argv passes through when -f flag is absent."""
        argv = ["file.py", "--verbose"]
        result = normalize_argv(argv)
        assert result == argv

    def test_normalize_argv_empty(self) -> None:
        """Test that normalize_argv handles empty argv."""
        argv: list[str] = []
        result = normalize_argv(argv)
        assert result == argv
