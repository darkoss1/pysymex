"""Tests for scanner integration pipeline types and core.

Targets the split modules:
  - pysymex.analysis.integration.types
  - pysymex.analysis.integration.core
  - pysymex.analysis.integration (hub re-exports)

These modules had ZERO test coverage prior to this file.
"""

from __future__ import annotations


import json

import os

import tempfile

import textwrap


import pytest


from pysymex.analysis.integration import (
    AnalysisConfig,
    AnalysisResult,
    FunctionContext,
    ModuleContext,
    ReportFormat,
    AnalysisSummary,
    AnalysisPipeline,
    ReportGenerator,
)


class TestAnalysisConfig:
    def test_defaults(self):
        cfg = AnalysisConfig()

        assert cfg.type_inference is True

        assert cfg.flow_analysis is True

        assert cfg.taint_analysis is True

        assert cfg.min_confidence == pytest.approx(0.5)

    def test_custom_values(self):
        cfg = AnalysisConfig(
            taint_analysis=False,
            min_confidence=0.8,
            timeout_per_function=10.0,
        )

        assert cfg.taint_analysis is False

        assert cfg.min_confidence == pytest.approx(0.8)

        assert cfg.timeout_per_function == pytest.approx(10.0)


class TestAnalysisResult:
    def test_construction(self):
        result = AnalysisResult(file_path="test.py")

        assert result.file_path == "test.py"

        assert result.issues == []

        assert result.analysis_time == 0.0

        assert result.functions_analyzed == 0

    def test_has_issues_empty(self):
        result = AnalysisResult(file_path="test.py")

        assert not result.has_issues()

    def test_total_count_zero(self):
        result = AnalysisResult(file_path="test.py")

        assert result.total_count() == 0

    def test_critical_and_high_count_zero(self):
        result = AnalysisResult(file_path="test.py")

        assert result.critical_count() == 0

        assert result.high_count() == 0


class TestReportFormat:
    def test_all_formats_exist(self):
        assert ReportFormat.TEXT is not None

        assert ReportFormat.JSON is not None

        assert ReportFormat.SARIF is not None

    def test_distinct_values(self):
        formats = {ReportFormat.TEXT, ReportFormat.JSON, ReportFormat.SARIF}

        assert len(formats) == 3


class TestFunctionContext:
    def test_construction(self):
        code = compile("x = 1", "<test>", "exec")

        ctx = FunctionContext(
            code=code,
            name="test_func",
            file_path="test.py",
            module_name="test_mod",
        )

        assert ctx.name == "test_func"

        assert ctx.file_path == "test.py"


class TestModuleContext:
    def test_construction(self):
        ctx = ModuleContext(
            file_path="test.py",
            module_name="test_mod",
            source_code="x = 1\n",
        )

        assert ctx.file_path == "test.py"

        assert ctx.module_name == "test_mod"


class TestAnalysisSummary:
    def test_default(self):
        summary = AnalysisSummary()

        assert summary.total_files == 0

        assert summary.total_issues == 0

    def test_from_results(self):
        r1 = AnalysisResult(file_path="a.py", functions_analyzed=3, lines_of_code=50)

        r2 = AnalysisResult(file_path="b.py", functions_analyzed=2, lines_of_code=30)

        summary = AnalysisSummary.from_results({"a.py": r1, "b.py": r2})

        assert summary.total_files == 2


class TestAnalysisPipeline:
    def test_construction_default(self):
        pipeline = AnalysisPipeline()

        assert pipeline is not None

    def test_construction_custom_config(self):
        cfg = AnalysisConfig(taint_analysis=False)

        pipeline = AnalysisPipeline(config=cfg)

        assert pipeline is not None

    def test_analyze_file(self):
        """Analyze a simple Python file."""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write(textwrap.dedent("""\
                def greet(name):
                    return "Hello, " + name
            """))

            f.flush()

            path = f.name

        try:
            pipeline = AnalysisPipeline()

            result = pipeline.analyze_file(path)

            assert isinstance(result, AnalysisResult)

            assert result.file_path == path

        finally:
            os.unlink(path)

    def test_analyze_file_with_bug(self):
        """Analyze a file with an obvious unbound variable."""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write(textwrap.dedent("""\
                def buggy():
                    return undefined_var
            """))

            f.flush()

            path = f.name

        try:
            pipeline = AnalysisPipeline()

            result = pipeline.analyze_file(path)

            assert isinstance(result, AnalysisResult)

        finally:
            os.unlink(path)

    def test_analyze_nonexistent_file(self):
        """Analyzing a nonexistent file should not crash."""

        pipeline = AnalysisPipeline()

        result = pipeline.analyze_file("/nonexistent/file.py")

        assert isinstance(result, AnalysisResult)

    def test_analyze_directory(self):
        """Analyze a temporary directory with Python files."""

        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(3):
                path = os.path.join(tmpdir, f"mod{i}.py")

                with open(path, "w", encoding="utf-8") as f:
                    f.write(f"x_{i} = {i}\n")

            pipeline = AnalysisPipeline()

            results = pipeline.analyze_directory(tmpdir)

            assert isinstance(results, dict)

            assert len(results) >= 3


class TestReportGenerator:
    @pytest.fixture()
    def sample_results(self):
        return {
            "a.py": AnalysisResult(file_path="a.py", functions_analyzed=2, lines_of_code=20),
            "b.py": AnalysisResult(file_path="b.py", functions_analyzed=1, lines_of_code=10),
        }

    def test_generate_text(self, sample_results):
        gen = ReportGenerator(sample_results)

        text = gen.generate_text()

        assert isinstance(text, str)

        assert len(text) > 0

    def test_generate_json(self, sample_results):
        gen = ReportGenerator(sample_results)

        output = gen.generate_json()

        assert isinstance(output, str)

        parsed = json.loads(output)

        assert isinstance(parsed, dict)

    def test_generate_sarif(self, sample_results):
        gen = ReportGenerator(sample_results)

        output = gen.generate_sarif()

        assert isinstance(output, str)

        parsed = json.loads(output)

        assert isinstance(parsed, dict)

    def test_empty_results(self):
        gen = ReportGenerator({})

        text = gen.generate_text()

        assert isinstance(text, str)


class TestScannerIntegrationHub:
    def test_types_accessible(self):
        from pysymex.analysis.integration import (
            AnalysisConfig,
            AnalysisResult,
            FunctionContext,
            ModuleContext,
            ReportFormat,
            AnalysisSummary,
        )

        assert all(
            c is not None
            for c in [
                AnalysisConfig,
                AnalysisResult,
                FunctionContext,
                ModuleContext,
                ReportFormat,
                AnalysisSummary,
            ]
        )

    def test_core_accessible(self):
        from pysymex.analysis.integration import (
            AnalysisPipeline,
            ReportGenerator,
        )

        assert AnalysisPipeline is not None

        assert ReportGenerator is not None

    def test_identity_types(self):
        from pysymex.analysis.integration.types import AnalysisConfig as T1

        from pysymex.analysis.integration import AnalysisConfig as T2

        assert T1 is T2

    def test_identity_core(self):
        from pysymex.analysis.integration.core import AnalysisPipeline as C1

        from pysymex.analysis.integration import AnalysisPipeline as C2

        assert C1 is C2
