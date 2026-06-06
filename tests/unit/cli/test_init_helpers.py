"""Tests for pysymex.cli helper functions."""

from __future__ import annotations

from pysymex.cli import is_issue_like_list, normalize_argv


class TestCliHelpers:
    """Test suite for pysymex.cli helper functions."""

    def testnormalize_argv_with_subcommand(self) -> None:
        """Test that normalize_argv passes through when subcommand is present."""
        argv = ["analyze", "file.py", "-f", "func"]
        result = normalize_argv(argv)
        assert result == argv

    def testnormalize_argv_without_function_flag(self) -> None:
        """Test that normalize_argv passes through when -f flag is absent."""
        argv = ["file.py", "--verbose"]
        result = normalize_argv(argv)
        assert result == argv

    def testnormalize_argv_empty(self) -> None:
        """Test that normalize_argv handles empty argv."""
        argv: list[str] = []
        result = normalize_argv(argv)
        assert result == argv

    def testis_issue_like_list_with_list_of_issues(self) -> None:
        """Test that is_issue_like_list returns True for list of issue-like objects."""

        class IssueLike:
            def to_dict(self) -> dict[str, object]:
                return {"type": "error"}

        issues = [IssueLike(), IssueLike()]
        assert is_issue_like_list(issues) is True

    def testis_issue_like_list_with_non_list(self) -> None:
        """Test that is_issue_like_list returns False for non-list."""
        assert is_issue_like_list("not a list") is False
        assert is_issue_like_list(123) is False
        assert is_issue_like_list(None) is False

    def testis_issue_like_list_with_mixed_list(self) -> None:
        """Test that is_issue_like_list returns False for mixed list."""

        class IssueLike:
            def to_dict(self) -> dict[str, object]:
                return {"type": "error"}

        mixed = [IssueLike(), "not issue"]
        assert is_issue_like_list(mixed) is False

    def testis_issue_like_list_with_empty_list(self) -> None:
        """Test that is_issue_like_list returns True for empty list."""
        assert is_issue_like_list([]) is True
