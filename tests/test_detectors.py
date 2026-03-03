"""Unit tests for issue detectors."""

import pytest

import z3

from pysymex.analysis.detectors import (
    Issue,
    IssueKind,
    DivisionByZeroDetector,
    DetectorRegistry,
)


class TestIssue:
    """Tests for Issue class."""

    def test_create_issue(self):
        """Test creating an issue."""

        issue = Issue(
            kind=IssueKind.DIVISION_BY_ZERO,
            message="Division by zero possible",
            line_number=10,
        )

        assert issue.kind == IssueKind.DIVISION_BY_ZERO

        assert issue.message == "Division by zero possible"

        assert issue.line_number == 10

    def test_issue_format(self):
        """Test issue formatting."""

        issue = Issue(
            kind=IssueKind.DIVISION_BY_ZERO,
            message="Test message",
            line_number=5,
        )

        formatted = issue.format()

        assert "DIVISION_BY_ZERO" in formatted

        assert "5" in formatted

        assert "Test message" in formatted

    def test_issue_to_dict(self):
        """Test issue serialization."""

        issue = Issue(
            kind=IssueKind.DIVISION_BY_ZERO,
            message="Test",
            line_number=10,
        )

        data = issue.to_dict()

        assert data["kind"] == "DIVISION_BY_ZERO"

        assert data["line_number"] == 10

        assert data["message"] == "Test"

    def test_get_counterexample_with_model(self):
        """Test counterexample extraction with Z3 model."""

        solver = z3.Solver()

        x = z3.Int("x")

        y = z3.Int("y")

        solver.add(x == 10)

        solver.add(y == 0)

        solver.check()

        model = solver.model()

        issue = Issue(
            kind=IssueKind.DIVISION_BY_ZERO,
            message="Test",
            model=model,
        )

        ce = issue.get_counterexample()

        assert "x" in ce

        assert "y" in ce

        assert ce["x"] == 10

        assert ce["y"] == 0


class TestIssueKind:
    """Tests for IssueKind enum."""

    def test_all_kinds_exist(self):
        """Test that all expected issue kinds exist."""

        assert hasattr(IssueKind, "DIVISION_BY_ZERO")

        assert hasattr(IssueKind, "ASSERTION_ERROR")

        assert hasattr(IssueKind, "INDEX_ERROR")

        assert hasattr(IssueKind, "KEY_ERROR")

        assert hasattr(IssueKind, "TYPE_ERROR")


class TestDetectorRegistry:
    """Tests for DetectorRegistry."""

    def test_default_registry(self):
        """Test that default registry has detectors."""

        from pysymex.analysis.detectors import default_registry

        detectors = default_registry.get_all()

        assert len(list(detectors)) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
