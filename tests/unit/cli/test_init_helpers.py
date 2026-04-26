"""Tests for pysymex.cli.__init__ helper functions."""

from __future__ import annotations

from pysymex.cli import _is_issue_like_list, _normalize_argv  # type: ignore[private]


class TestCliHelpers:
    """Test suite for pysymex.cli.__init__ helper functions."""

    def test_normalize_argv_with_subcommand(self) -> None:
        """Test that _normalize_argv passes through when subcommand is present."""
        argv = ["analyze", "file.py", "-f", "func"]
        result = _normalize_argv(argv)
        assert result == argv

    def test_normalize_argv_with_legacy_syntax(self) -> None:
        """Test that _normalize_argv converts legacy syntax to modern form."""
        argv = ["file.py", "-f", "func"]
        result = _normalize_argv(argv)
        assert result == ["analyze", "file.py", "-f", "func"]

    def test_normalize_argv_without_function_flag(self) -> None:
        """Test that _normalize_argv passes through when -f flag is absent."""
        argv = ["file.py", "--verbose"]
        result = _normalize_argv(argv)
        assert result == argv

    def test_normalize_argv_empty(self) -> None:
        """Test that _normalize_argv handles empty argv."""
        argv: list[str] = []
        result = _normalize_argv(argv)
        assert result == argv

    def test_is_issue_like_list_with_list_of_issues(self) -> None:
        """Test that _is_issue_like_list returns True for list of issue-like objects."""

        class IssueLike:
            def to_dict(self) -> dict[str, object]:
                return {"type": "error"}

        issues = [IssueLike(), IssueLike()]
        assert _is_issue_like_list(issues) is True

    def test_is_issue_like_list_with_non_list(self) -> None:
        """Test that _is_issue_like_list returns False for non-list."""
        assert _is_issue_like_list("not a list") is False
        assert _is_issue_like_list(123) is False
        assert _is_issue_like_list(None) is False

    def test_is_issue_like_list_with_mixed_list(self) -> None:
        """Test that _is_issue_like_list returns False for mixed list."""

        class IssueLike:
            def to_dict(self) -> dict[str, object]:
                return {"type": "error"}

        mixed = [IssueLike(), "not issue"]
        assert _is_issue_like_list(mixed) is False

    def test_is_issue_like_list_with_empty_list(self) -> None:
        """Test that _is_issue_like_list returns True for empty list."""
        assert _is_issue_like_list([]) is True
