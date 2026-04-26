from __future__ import annotations

from pathlib import Path

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.execution.types import BRANCH_OPCODES, ExecutionConfig, ExecutionResult


class TestExecutionConfig:
    """Test suite for pysymex.execution.types.ExecutionConfig."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        cfg = ExecutionConfig(max_paths=123, enable_chtd=False, deterministic_mode=True)

        assert cfg.max_paths == 123
        assert cfg.enable_chtd is False
        assert cfg.deterministic_mode is True
        assert "FOR_ITER" in BRANCH_OPCODES


class TestExecutionResult:
    """Test suite for pysymex.execution.types.ExecutionResult."""

    def test_has_issues(self) -> None:
        """Test has_issues behavior."""
        empty = ExecutionResult()
        issue = Issue(kind=IssueKind.TYPE_ERROR, message="boom")
        non_empty = ExecutionResult(issues=[issue])

        assert empty.has_issues() is False
        assert non_empty.has_issues() is True

    def test_get_issues_by_kind(self) -> None:
        """Test get_issues_by_kind behavior."""
        type_issue = Issue(kind=IssueKind.TYPE_ERROR, message="type")
        key_issue = Issue(kind=IssueKind.KEY_ERROR, message="key")
        result = ExecutionResult(issues=[type_issue, key_issue])

        only_type = result.get_issues_by_kind(IssueKind.TYPE_ERROR)

        assert only_type == [type_issue]

    def test_format_summary(self) -> None:
        """Test format_summary behavior."""
        result = ExecutionResult(
            function_name="f",
            paths_explored=2,
            paths_completed=1,
            total_time_seconds=0.5,
            coverage={0, 2},
        )

        summary = result.format_summary()

        assert "Function: f" in summary
        assert "Paths explored: 2" in summary
        assert "No issues found!" in summary

    def test_to_dict(self) -> None:
        """Test to_dict behavior."""
        issue = Issue(kind=IssueKind.VALUE_ERROR, message="bad", filename="m.py", line_number=7)
        result = ExecutionResult(
            issues=[issue],
            function_name="f",
            source_file="m.py",
            paths_explored=3,
            paths_completed=2,
            paths_pruned=1,
            coverage={1, 9},
            total_time_seconds=1.2,
        )

        as_dict = result.to_dict()

        assert as_dict["function_name"] == "f"
        assert as_dict["source_file"] == "m.py"
        assert as_dict["coverage_size"] == 2
        assert isinstance(as_dict["issues"], list)

    def test_to_sarif(self) -> None:
        """Test to_sarif behavior."""
        issue = Issue(
            kind=IssueKind.DIVISION_BY_ZERO,
            message="possible division by zero",
            filename="a.py",
            line_number=12,
        )
        result = ExecutionResult(
            issues=[issue],
            function_name="f",
            source_file="a.py",
            paths_explored=4,
            paths_completed=3,
            paths_pruned=1,
            coverage={1, 2, 3},
            total_time_seconds=0.01,
        )
        out = Path(".pytest_cache") / "execution-result.sarif"
        out.parent.mkdir(parents=True, exist_ok=True)

        sarif = result.to_sarif(str(out))

        assert isinstance(sarif, dict)
        assert "runs" in sarif
        assert out.exists()
