import pytest
from pysymex.analysis.integration.types import (
    AnalysisConfig, AnalysisResult, AnalysisResultBuilder,
    FunctionContext, ModuleContext, ReportFormat, AnalysisSummary
)
from pysymex.analysis.detectors.types import Issue, IssueKind, Severity
from pysymex.analysis.taint.types import TaintViolation, TaintSink, SinkKind, TaintSource

class TestAnalysisConfig:
    """Test suite for pysymex.analysis.integration.types.AnalysisConfig."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        config = AnalysisConfig()
        assert config.type_inference is True
        assert config.flow_analysis is True

class TestAnalysisResult:
    """Test suite for pysymex.analysis.integration.types.AnalysisResult."""
    def test_has_issues(self) -> None:
        """Test has_issues behavior."""
        res = AnalysisResult("file.py")
        assert res.has_issues() is False
        res.issues.append(Issue(IssueKind.UNKNOWN, Severity.INFO, "file.py", 10, "msg"))
        assert res.has_issues() is True

    def test_critical_count(self) -> None:
        """Test critical_count behavior."""
        res = AnalysisResult("file.py")
        res.issues.append(Issue(IssueKind.UNKNOWN, Severity.CRITICAL, "file.py", 10, "msg"))
        assert res.critical_count() == 1

    def test_high_count(self) -> None:
        """Test high_count behavior."""
        res = AnalysisResult("file.py")
        res.issues.append(Issue(IssueKind.UNKNOWN, Severity.HIGH, "file.py", 10, "msg"))
        assert res.high_count() == 1

    def test_total_count(self) -> None:
        """Test total_count behavior."""
        res = AnalysisResult("file.py")
        res.issues.append(Issue(IssueKind.UNKNOWN, Severity.INFO, "file.py", 10, "msg"))
        assert res.total_count() == 1

class TestAnalysisResultBuilder:
    """Test suite for pysymex.analysis.integration.types.AnalysisResultBuilder."""
    def test_add_issue(self) -> None:
        """Test add_issue behavior."""
        b = AnalysisResultBuilder("file.py")
        b.add_issue(Issue(IssueKind.UNKNOWN, Severity.INFO, "file.py", 10, "msg"))
        assert len(b.issues) == 1

    def test_add_taint_violation(self) -> None:
        """Test add_taint_violation behavior."""
        b = AnalysisResultBuilder("file.py")
        sink = TaintSink(SinkKind.SQL_EXECUTE, Severity.HIGH, "db.execute")
        source = TaintSource("user_input", 1)
        b.add_taint_violation(TaintViolation(sink, source, 10, 5, "file.py", "x", "path"))
        assert len(b.taint_violations) == 1

    def test_add_warning(self) -> None:
        """Test add_warning behavior."""
        b = AnalysisResultBuilder("file.py")
        b.add_warning("warn")
        assert len(b.warnings) == 1

    def test_increment_functions(self) -> None:
        """Test increment_functions behavior."""
        b = AnalysisResultBuilder("file.py")
        b.increment_functions()
        assert b.functions_analyzed == 1

    def test_build(self) -> None:
        """Test build behavior."""
        b = AnalysisResultBuilder("file.py")
        res = b.build()
        assert res.file_path == "file.py"
        assert res.functions_analyzed == 0

class TestFunctionContext:
    """Test suite for pysymex.analysis.integration.types.FunctionContext."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        def f() -> None: pass
        ctx = FunctionContext(f.__code__, "f", "file.py", "module")
        assert ctx.name == "f"
        assert ctx.file_path == "file.py"

class TestModuleContext:
    """Test suite for pysymex.analysis.integration.types.ModuleContext."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        ctx = ModuleContext("file.py", "module", "code")
        assert ctx.module_name == "module"
        assert ctx.source_code == "code"

class TestReportFormat:
    """Test suite for pysymex.analysis.integration.types.ReportFormat."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert ReportFormat.JSON.name == "JSON"

class TestAnalysisSummary:
    """Test suite for pysymex.analysis.integration.types.AnalysisSummary."""
    def test_from_results(self) -> None:
        """Test from_results behavior."""
        res1 = AnalysisResult("f1.py", issues=[Issue(IssueKind.UNKNOWN, Severity.CRITICAL, "f1.py", 10, "m1")])
        res2 = AnalysisResult("f2.py", issues=[Issue(IssueKind.UNKNOWN, Severity.HIGH, "f2.py", 10, "m2")])
        summary = AnalysisSummary.from_results({"f1.py": res1, "f2.py": res2})
        assert summary.total_files == 2
        assert summary.critical_count == 1
        assert summary.high_count == 1
