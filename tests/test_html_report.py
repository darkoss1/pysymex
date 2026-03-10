"""Tests for HTML report generation."""

from datetime import datetime

from pysymex.reporting.html_report import (
    AnalysisReport,
    IssueReport,
    generate_html_report,
)
from pysymex.resources import ResourceSnapshot


class TestIssueReport:
    """Tests for IssueReport."""

    def test_create_issue_report(self):
        """Test creating an issue report."""
        issue = IssueReport(
            severity="critical",
            issue_type="DIVISION_BY_ZERO",
            message="Division by zero detected",
            file_path="test.py",
            line_number=10,
        )

        assert issue.severity == "critical"
        assert issue.issue_type == "DIVISION_BY_ZERO"
        assert issue.line_number == 10

    def test_to_dict(self):
        """Test conversion to dictionary."""
        issue = IssueReport(
            severity="warning",
            issue_type="POSSIBLE_NULL",
            message="May be null",
        )

        d = issue.to_dict()

        assert d["severity"] == "warning"
        assert d["type"] == "POSSIBLE_NULL"
        assert d["message"] == "May be null"

    def test_with_triggering_input(self):
        """Test issue with triggering input."""
        issue = IssueReport(
            severity="critical",
            issue_type="DIV_ZERO",
            message="Division by zero",
            triggering_input={"x": 10, "y": 0},
        )

        d = issue.to_dict()

        assert d["input"] == {"x": 10, "y": 0}


class TestAnalysisReport:
    """Tests for AnalysisReport."""

    def test_create_report(self):
        """Test creating an analysis report."""
        report = AnalysisReport(
            title="Test Analysis",
            timestamp=datetime.now().isoformat(),
            duration_seconds=1.5,
            file_path="test.py",
            function_name="test_func",
        )

        assert report.title == "Test Analysis"
        assert report.function_name == "test_func"
        assert report.duration_seconds == 1.5

    def test_report_with_issues(self):
        """Test report with issues."""
        issues = [
            IssueReport(severity="critical", issue_type="DIV", message="Division"),
            IssueReport(severity="warning", issue_type="IDX", message="Index"),
        ]

        report = AnalysisReport(
            title="Test",
            timestamp="2024-01-01",
            duration_seconds=1.0,
            issues=issues,
        )

        assert len(report.issues) == 2

    def test_to_dict(self):
        """Test conversion to dictionary."""
        report = AnalysisReport(
            title="Analysis",
            timestamp="2024-01-01",
            duration_seconds=2.5,
            paths_explored=100,
            success=True,
        )

        d = report.to_dict()

        assert d["title"] == "Analysis"
        assert d["paths_explored"] == 100
        assert d["success"] is True


class TestHTMLGeneration:
    """Tests for HTML report generation."""

    def test_generate_basic_report(self):
        """Test generating a basic HTML report."""
        report = AnalysisReport(
            title="Test Analysis",
            timestamp="2024-01-01T12:00:00",
            duration_seconds=1.5,
            file_path="example.py",
            function_name="divide",
            paths_explored=50,
        )

        html = generate_html_report(report)

        assert "<!DOCTYPE html>" in html
        assert "Test Analysis" in html
        assert "example.py" in html
        assert "divide" in html

    def test_generate_report_with_issues(self):
        """Test generating report with issues."""
        issues = [
            IssueReport(
                severity="critical",
                issue_type="DIVISION_BY_ZERO",
                message="Potential division by zero",
                file_path="calc.py",
                line_number=42,
            ),
        ]

        report = AnalysisReport(
            title="Analysis with Issues",
            timestamp="2024-01-01",
            duration_seconds=1.0,
            issues=issues,
            file_path="calc.py",
            function_name="calculate",
            paths_explored=25,
        )

        html = generate_html_report(report)

        assert "DIVISION_BY_ZERO" in html
        assert "Potential division by zero" in html
        assert "calc.py:42" in html

    def test_generate_report_no_issues(self):
        """Test generating report with no issues."""
        report = AnalysisReport(
            title="Clean Analysis",
            timestamp="2024-01-01",
            duration_seconds=0.5,
            issues=[],
            success=True,
            file_path="clean.py",
            function_name="safe_func",
            paths_explored=10,
        )

        html = generate_html_report(report)

        assert "No Issues Found" in html
        assert "✓" in html or "Complete" in html

    def test_generate_report_with_resources(self):
        """Test generating report with resource snapshot."""
        resources = ResourceSnapshot(
            paths_explored=100,
            max_depth_reached=15,
            iterations=500,
            elapsed_time=2.5,
            solver_calls=50,
            cache_hits=30,
        )

        report = AnalysisReport(
            title="Resource Report",
            timestamp="2024-01-01",
            duration_seconds=2.5,
            resources=resources,
            file_path="test.py",
            function_name="func",
            paths_explored=100,
        )

        html = generate_html_report(report)

        assert "100" in html  # paths
        assert "15" in html  # max depth

    def test_generate_report_partial(self):
        """Test generating report for partial analysis."""
        report = AnalysisReport(
            title="Partial Analysis",
            timestamp="2024-01-01",
            duration_seconds=60.0,
            partial=True,
            file_path="big.py",
            function_name="complex_func",
            paths_explored=500,
        )

        html = generate_html_report(report)

        assert "Partial" in html

    def test_generate_report_error(self):
        """Test generating report with error."""
        report = AnalysisReport(
            title="Failed Analysis",
            timestamp="2024-01-01",
            duration_seconds=0.1,
            success=False,
            error_message="Function not found",
            file_path="missing.py",
            function_name="nonexistent",
            paths_explored=0,
        )

        html = generate_html_report(report)

        assert "Error" in html

    def test_html_escaping(self):
        """Test that HTML content is properly escaped."""
        issue = IssueReport(
            severity="critical",
            issue_type="XSS",
            message="<script>alert('xss')</script>",
        )

        report = AnalysisReport(
            title="XSS Test<script>",
            timestamp="2024-01-01",
            duration_seconds=1.0,
            issues=[issue],
            file_path="test.py",
            function_name="test",
            paths_explored=1,
        )

        html = generate_html_report(report)

        # Should be escaped, not raw
        assert "<script>alert" not in html
        assert "&lt;script&gt;" in html

    def test_html_has_styling(self):
        """Test that HTML includes styling."""
        report = AnalysisReport(
            title="Styled Report",
            timestamp="2024-01-01",
            duration_seconds=1.0,
            file_path="test.py",
            function_name="test",
            paths_explored=1,
        )

        html = generate_html_report(report)

        assert "<style>" in html
        assert "</style>" in html
        assert "background" in html.lower() or "color" in html.lower()

    def test_html_is_standalone(self):
        """Test that HTML is a complete standalone document."""
        report = AnalysisReport(
            title="Standalone",
            timestamp="2024-01-01",
            duration_seconds=1.0,
            file_path="test.py",
            function_name="test",
            paths_explored=1,
        )

        html = generate_html_report(report)

        assert html.startswith("<!DOCTYPE html>")
        assert "<html" in html
        assert "</html>" in html
        assert "<head>" in html
        assert "<body>" in html
