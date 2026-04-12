import pytest
from unittest.mock import Mock, patch
from pysymex.analysis.pipeline.phases import (
    TypeInferencePhase, PatternRecognitionPhase, FlowAnalysisPhase,
    BugDetectionPhase, DeadCodePhase, ResourcePhase, SecurityPhase, ExceptionPhase,
    apply_common_suppression, apply_exception_suppression,
    is_used_in_annotations, is_function_or_class_def,
    extract_var_name_from_message, group_issues
)
from pysymex.analysis.pipeline.types import AnalysisContext, ScannerConfig, ScanIssue, IssueCategory
from pysymex.analysis.detectors.types import Issue, IssueKind, Severity
from pysymex.analysis.patterns import PatternMatch, PatternKind

def make_dummy_ctx() -> AnalysisContext:
    # Use compile to make a code object so _cached_get_instructions works
    code = compile("def f(): pass", "f.py", "exec")
    return AnalysisContext(
        file_path="f.py",
        source="def f(): pass",
        code=code
    )

class TestTypeInferencePhase:
    """Test suite for pysymex.analysis.pipeline.phases.TypeInferencePhase."""
    def test_analyze(self) -> None:
        """Test analyze behavior."""
        p = TypeInferencePhase()
        cfg = ScannerConfig(enable_type_inference=False)
        assert len(p.analyze(make_dummy_ctx(), cfg)) == 0

class TestPatternRecognitionPhase:
    """Test suite for pysymex.analysis.pipeline.phases.PatternRecognitionPhase."""
    def test_analyze(self) -> None:
        """Test analyze behavior."""
        p = PatternRecognitionPhase()
        cfg = ScannerConfig(enable_pattern_recognition=False)
        assert len(p.analyze(make_dummy_ctx(), cfg)) == 0

class TestFlowAnalysisPhase:
    """Test suite for pysymex.analysis.pipeline.phases.FlowAnalysisPhase."""
    def test_analyze(self) -> None:
        """Test analyze behavior."""
        p = FlowAnalysisPhase()
        cfg = ScannerConfig(enable_flow_analysis=False)
        assert len(p.analyze(make_dummy_ctx(), cfg)) == 0

class TestBugDetectionPhase:
    """Test suite for pysymex.analysis.pipeline.phases.BugDetectionPhase."""
    @patch("pysymex.analysis.pipeline.phases.filter_issue")
    def test_analyze(self, mock_filter_issue) -> None:
        """Test analyze behavior."""
        p = BugDetectionPhase()
        p.analyzer.analyze_function = Mock(return_value=[
            Issue(IssueKind.DIVISION_BY_ZERO, Severity.HIGH, "f.py", 10, "msg")
        ])
        mock_filter = Mock()
        mock_filter.should_filter = False
        mock_filter_issue.return_value = mock_filter
        
        ctx = make_dummy_ctx()
        cfg = ScannerConfig()
        issues = p.analyze(ctx, cfg)
        assert len(issues) == 1
        assert issues[0].kind == "DIVISION_BY_ZERO"

def test_apply_common_suppression() -> None:
    """Test apply_common_suppression behavior."""
    ctx = make_dummy_ctx()
    issue = ScanIssue(IssueCategory.BUG, "UNUSED_VARIABLE", "warning", "f.py", 10, "Variable 'x' is unused", 0.9)
    apply_common_suppression(issue, ctx)
    issue2 = ScanIssue(IssueCategory.BUG, "UNUSED_VARIABLE", "warning", "f.py", 10, "Variable '_y' is unused", 0.9)
    apply_common_suppression(issue2, ctx)
    assert issue2.confidence < 0.9

def test_apply_exception_suppression() -> None:
    """Test apply_exception_suppression behavior."""
    ctx = make_dummy_ctx()
    issue = ScanIssue(IssueCategory.BUG, "TOO_BROAD_EXCEPT", "info", "f.py", 10, "msg", 0.9)
    apply_exception_suppression(issue, ctx)
    assert issue.confidence == 0.0
    assert len(issue.suppression_reasons) > 0

def test_is_used_in_annotations() -> None:
    """Test is_used_in_annotations behavior."""
    source = "def f(a: MyType):\n    pass"
    assert is_used_in_annotations("MyType", source) is True
    assert is_used_in_annotations("OtherType", source) is False
    assert is_used_in_annotations("MyType", "syntax error {") is False

def test_is_function_or_class_def() -> None:
    """Test is_function_or_class_def behavior."""
    source = "def my_func(): pass\nclass MyClass: pass"
    assert is_function_or_class_def("my_func", source) is True
    assert is_function_or_class_def("MyClass", source) is True
    assert is_function_or_class_def("other", source) is False

def test_extract_var_name_from_message() -> None:
    """Test extract_var_name_from_message behavior."""
    msg = "Variable 'my_var' is unused"
    assert extract_var_name_from_message(msg) == "my_var"
    assert extract_var_name_from_message("No quotes here") == ""

def test_group_issues() -> None:
    """Test group_issues behavior."""
    i1 = ScanIssue(IssueCategory.BUG, "KIND", "high", "f1", 10, "msg1", 0.9, function_name="f")
    i2 = ScanIssue(IssueCategory.BUG, "KIND", "high", "f1", 20, "msg2", 0.9, function_name="f")
    grouped = group_issues([i1, i2])
    assert len(grouped[("f1", "f", "KIND")]) == 2

class TestDeadCodePhase:
    """Test suite for pysymex.analysis.pipeline.phases.DeadCodePhase."""
    def test_analyze(self) -> None:
        """Test analyze behavior."""
        p = DeadCodePhase()
        cfg = ScannerConfig(enable_dead_code=False)
        assert len(p.analyze(make_dummy_ctx(), cfg)) == 0

class TestResourcePhase:
    """Test suite for pysymex.analysis.pipeline.phases.ResourcePhase."""
    def test_analyze(self) -> None:
        """Test analyze behavior."""
        p = ResourcePhase()
        cfg = ScannerConfig(enable_resource_analysis=False)
        assert len(p.analyze(make_dummy_ctx(), cfg)) == 0

class TestSecurityPhase:
    """Test suite for pysymex.analysis.pipeline.phases.SecurityPhase."""
    def test_analyze(self) -> None:
        """Test analyze behavior."""
        p = SecurityPhase()
        cfg = ScannerConfig(enable_taint_analysis=False, enable_string_analysis=False)
        assert len(p.analyze(make_dummy_ctx(), cfg)) == 0

class TestExceptionPhase:
    """Test suite for pysymex.analysis.pipeline.phases.ExceptionPhase."""
    def test_analyze(self) -> None:
        """Test analyze behavior."""
        p = ExceptionPhase()
        cfg = ScannerConfig(enable_exception_analysis=False)
        assert len(p.analyze(make_dummy_ctx(), cfg)) == 0
