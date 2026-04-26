import pytest
from pysymex.analysis.pipeline.types import (
    ScannerConfig,
    IssueCategory,
    ScanIssue,
    AnalysisContext,
    AnalysisPhase,
)


class TestNoneCheckAnalyzerLike:
    """Test suite for pysymex.analysis.pipeline.types.NoneCheckAnalyzerLike."""

    def test_is_none_safe(self) -> None:
        """Test is_none_safe behavior."""
        # Protocol class, nothing to test directly
        pass


class TestScannerConfig:
    """Test suite for pysymex.analysis.pipeline.types.ScannerConfig."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        cfg = ScannerConfig(min_confidence=0.5)
        assert cfg.min_confidence == 0.5
        assert cfg.enable_type_inference is True


class TestIssueCategory:
    """Test suite for pysymex.analysis.pipeline.types.IssueCategory."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert IssueCategory.BUG.name == "BUG"


class TestScanIssue:
    """Test suite for pysymex.analysis.pipeline.types.ScanIssue."""

    def test_is_suppressed(self) -> None:
        """Test is_suppressed behavior."""
        issue = ScanIssue(IssueCategory.BUG, "K", "high", "f", 1, "m", 0.9)
        assert issue.is_suppressed() is False
        issue.suppression_reasons.append("reason")
        assert issue.is_suppressed() is True

    def test_to_dict(self) -> None:
        """Test to_dict behavior."""
        issue = ScanIssue(IssueCategory.BUG, "K", "high", "f", 1, "m", 0.9)
        d = issue.to_dict()
        assert d["category"] == "BUG"
        assert d["kind"] == "K"

    def test_attach_suggestion(self) -> None:
        """Test attach_suggestion behavior."""
        issue = ScanIssue(IssueCategory.BUG, "DIVISION_BY_ZERO", "high", "f", 1, "m", 0.9)
        issue.attach_suggestion()
        assert "zero-check guard" in issue.suggestion


class TestAnalysisContext:
    """Test suite for pysymex.analysis.pipeline.types.AnalysisContext."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        import types

        def f() -> None:
            pass

        ctx = AnalysisContext("f.py", "def f(): pass", f.__code__)
        assert ctx.file_path == "f.py"
        assert isinstance(ctx.types, dict)


class TestAnalysisPhase:
    """Test suite for pysymex.analysis.pipeline.types.AnalysisPhase."""

    def test_analyze(self) -> None:
        """Test analyze behavior."""
        p = AnalysisPhase()
        with pytest.raises(NotImplementedError):
            p.analyze(None, None)
