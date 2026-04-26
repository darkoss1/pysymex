import pytest
from unittest.mock import Mock, patch
from pathlib import Path
import tempfile
from pysymex.analysis.integration.core import AnalysisPipeline, ReportGenerator
from pysymex.analysis.integration.types import AnalysisConfig, ModuleContext
from pysymex.analysis.detectors.types import Issue, IssueKind, Severity


def make_dummy_code() -> object:
    def f() -> None:
        pass

    return f.__code__


class TestAnalysisPipeline:
    """Test suite for pysymex.analysis.integration.core.AnalysisPipeline."""

    def test_analyze_source(self) -> None:
        """Test analyze_source behavior."""
        pipeline = AnalysisPipeline()
        res = pipeline.analyze_source("def f(): pass", "test.py")
        assert res.file_path == "test.py"
        assert res.functions_analyzed > 0

        res_err = pipeline.analyze_source("def f(:", "test.py")
        assert res_err.has_issues() is True
        assert any(i.kind == IssueKind.SYNTAX_ERROR for i in res_err.issues)

    def test_analyze_file(self) -> None:
        """Test analyze_file behavior."""
        pipeline = AnalysisPipeline()
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write("def f(): pass\n")
            name = f.name

        try:
            res = pipeline.analyze_file(name)
            assert res.functions_analyzed > 0
        finally:
            import os

            os.remove(name)

    def test_extract_imports(self) -> None:
        """Test extract_imports behavior."""
        pipeline = AnalysisPipeline()
        code = compile("import math\nimport os", "test.py", "exec")
        ctx = ModuleContext("test.py", "test", "import math\nimport os", code=code)
        pipeline.extract_imports(ctx)
        assert "math" in ctx.imports
        assert "os" in ctx.imports

    def test_analyze_directory(self) -> None:
        """Test analyze_directory behavior."""
        pipeline = AnalysisPipeline()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "test.py"
            p.write_text("def f(): pass\n")
            res = pipeline.analyze_directory(td)
            assert len(res) == 1
            assert str(p.absolute()) in res


class TestReportGenerator:
    """Test suite for pysymex.analysis.integration.core.ReportGenerator."""

    def test_generate_text(self) -> None:
        """Test generate_text behavior."""
        res = Mock()
        res.has_issues.return_value = True
        res.issues = [Issue(IssueKind.UNKNOWN, Severity.CRITICAL, "test.py", 10, "msg")]
        res.analysis_time = 1.0
        res.lines_of_code = 10
        res.functions_analyzed = 1

        gen = ReportGenerator({"test.py": res})
        text = gen.generate_text()
        assert "test.py" in text
        assert "msg" in text

    def test_generate_json(self) -> None:
        """Test generate_json behavior."""
        res = Mock()
        res.issues = [Issue(IssueKind.UNKNOWN, Severity.CRITICAL, "test.py", 10, "msg")]
        res.analysis_time = 1.0
        res.lines_of_code = 10
        res.functions_analyzed = 1

        gen = ReportGenerator({"test.py": res})
        js = gen.generate_json()
        assert "test.py" in js
        assert "msg" in js

    def test_generate_sarif(self) -> None:
        """Test generate_sarif behavior."""
        res = Mock()
        res.issues = [Issue(IssueKind.UNKNOWN, Severity.CRITICAL, "test.py", 10, "msg")]
        res.analysis_time = 1.0
        res.lines_of_code = 10
        res.functions_analyzed = 1

        gen = ReportGenerator({"test.py": res})
        sarif = gen.generate_sarif()
        assert "test.py" in sarif
        assert "msg" in sarif
