from __future__ import annotations

from pathlib import Path

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.execution.constants import BRANCH_OPCODES
from pysymex.execution.config.settings import ExecutionConfig
from pysymex.execution.results.result import ExecutionResult


class TestExecutionConfig:
    """Test suite for pysymex.execution.config.settings.ExecutionConfig."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        cfg = ExecutionConfig(max_paths=123, deterministic_mode=True)

        assert cfg.max_paths == 123
        assert cfg.deterministic_mode is True
        assert "FOR_ITER" in BRANCH_OPCODES


class TestExecutionResult:
    """Test suite for pysymex.execution.results.result.ExecutionResult."""

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

    def test_degraded_summary_and_sarif_do_not_claim_success(self) -> None:
        result = ExecutionResult(degraded_passes=["solver_unknown_detector_query"])

        summary = result.format_summary()
        sarif = result.to_sarif()
        invocation = sarif["runs"][0]["invocations"][0]  # type: ignore[index]

        assert "Analysis degraded: solver_unknown_detector_query" in summary
        assert "No issues found!" not in summary
        assert invocation["executionSuccessful"] is False  # type: ignore[index]
        assert invocation["properties"]["degradedPasses"] == [  # type: ignore[index]
            "solver_unknown_detector_query"
        ]

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
        assert as_dict["degraded_passes"] == []

    def test_to_sarif(self, tmp_path: Path) -> None:
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
        out = tmp_path / "execution-result.sarif"

        sarif = result.to_sarif(str(out))

        assert isinstance(sarif, dict)
        assert "runs" in sarif
        assert out.exists()
