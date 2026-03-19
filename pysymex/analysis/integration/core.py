"""
Scanner Integration Core for pysymex.
Core analysis pipeline and report generation logic.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import (
    cast,
)

from pysymex.core.instruction_cache import get_instructions as _cached_get_instructions

from ..abstract.interpreter import (
    AbstractAnalyzer,
    DivisionByZeroWarning,
)
from ..detectors.static_types import (
    DetectionContext,
    Issue,
    IssueKind,
    Severity,
)
from ..detectors.static import StaticAnalyzer
from ..flow_sensitive import (
    CFGBuilder,
    FlowSensitiveAnalyzer,
)
from ..function_models import (
    FunctionSummarizer,
)
from ..patterns import (
    PatternAnalyzer,
    PatternKind,
    PatternMatch,
)
from ..taint.checker import (
    TaintChecker,
)
from ..type_inference import (
    TypeAnalyzer,
    TypeEnvironment,
)
from .types import (
    AnalysisConfig,
    AnalysisResult,
    AnalysisResultBuilder,
    AnalysisSummary,
    FunctionContext,
    ModuleContext,
)

logger = logging.getLogger(__name__)


class AnalysisPipeline:
    """Main analysis pipeline integrating all analysis components.

    Orchestrates type inference, flow analysis, pattern recognition,
    taint checking, abstract interpretation, and static detection.

    Attributes:
        config: Pipeline configuration.
        type_analyzer: Type inference engine.
        flow_analyzer: Flow-sensitive analyser (created per function).
        pattern_analyzer: Pattern recognizer.
        taint_checker: Taint-flow checker.
        abstract_analyzer: Abstract-interpretation engine.
        enhanced_analyzer: Static detector engine.
        function_models: Function summarizer for inter-procedural analysis.
    """

    def __init__(self, config: AnalysisConfig | None = None) -> None:
        self.config = config or AnalysisConfig()
        self.type_analyzer = TypeAnalyzer()
        self.flow_analyzer: FlowSensitiveAnalyzer | None = None
        self.pattern_analyzer = PatternAnalyzer()
        self.taint_checker = TaintChecker()
        self.abstract_analyzer = AbstractAnalyzer()
        self.enhanced_analyzer = StaticAnalyzer()
        self.function_models = FunctionSummarizer()
        self._setup_patterns()

    def _get_flow_analyzer(self, code: object) -> FlowSensitiveAnalyzer:
        """Create a FlowSensitiveAnalyzer for the given code object."""
        return FlowSensitiveAnalyzer(code)

    def _setup_patterns(self) -> None:
        """Set up pattern recognizers."""

    def analyze_source(self, source: str, file_path: str = "<source>") -> AnalysisResult:
        """Analyse already-loaded source text (no file I/O).

        This is the functional core of :meth:`analyze_file`. Callers
        supply the source string so that I/O happens only at the shell.
        """
        builder = AnalysisResultBuilder(file_path=file_path)
        start_time = time.time()
        try:
            builder.lines_of_code = len(source.splitlines())
            code = compile(source, file_path, "exec")
            module_name = Path(file_path).stem
            module_ctx = ModuleContext(
                file_path=file_path,
                module_name=module_name,
                source_code=source,
                code=code,
            )
            self._analyze_module(module_ctx, builder)
        except SyntaxError as e:
            builder.add_issue(
                Issue(
                    kind=IssueKind.SYNTAX_ERROR,
                    severity=Severity.CRITICAL,
                    message=f"Syntax error: {e.msg}",
                    file=file_path,
                    line=e.lineno or 0,
                    column=e.offset or 0,
                    confidence=1.0,
                )
            )
        except (ValueError, TypeError, RuntimeError) as e:
            builder.add_warning(f"Analysis error: {type(e).__name__}: {e}")
        builder.analysis_time = time.time() - start_time
        return builder.build()

    def analyze_file(self, file_path: str) -> AnalysisResult:
        """Analyze a single Python file (I/O shell).

        Reads the file and delegates to :meth:`analyze_source`.
        """
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                source = f.read()
        except OSError as e:
            builder = AnalysisResultBuilder(file_path=file_path)
            builder.add_warning(f"Read error: {e}")
            return builder.build()
        return self.analyze_source(source, file_path)

    def _analyze_module(
        self,
        module_ctx: ModuleContext,
        builder: AnalysisResultBuilder,
    ) -> None:
        """Analyze all code in a module."""
        if not module_ctx.code:
            return
        self._extract_imports(module_ctx)
        module_func_ctx = FunctionContext(
            code=module_ctx.code,
            name="<module>",
            file_path=module_ctx.file_path,
            module_name=module_ctx.module_name,
        )
        self._analyze_function(module_func_ctx, module_ctx, builder)
        builder.increment_functions()
        self._find_functions(module_ctx.code, module_ctx, builder)

    def _extract_imports(self, module_ctx: ModuleContext) -> None:
        """Extract import information from the module."""
        if not module_ctx.code:
            return
        for const in module_ctx.code.co_consts:
            if isinstance(const, str):
                module_ctx.imports.add(const)
        for instr in _cached_get_instructions(module_ctx.code):
            if instr.opname == "IMPORT_NAME":
                module_ctx.imports.add(str(instr.argval))

    def _find_functions(
        self,
        code: object,
        module_ctx: ModuleContext,
        builder: AnalysisResultBuilder,
        parent_ctx: FunctionContext | None = None,
    ) -> None:
        """Recursively find and analyze all functions."""
        for const in code.co_consts:
            if hasattr(const, "co_code"):
                func_ctx = FunctionContext(
                    code=const,
                    name=const.co_name,
                    file_path=module_ctx.file_path,
                    module_name=module_ctx.module_name,
                    parent=parent_ctx,
                )
                module_ctx.functions[const.co_name] = func_ctx
                self._analyze_function(func_ctx, module_ctx, builder)
                builder.increment_functions()
                self._find_functions(const, module_ctx, builder, func_ctx)

    def _analyze_function(
        self,
        func_ctx: FunctionContext,
        module_ctx: ModuleContext,
        builder: AnalysisResultBuilder,
    ) -> None:
        """Run all analysis phases on a function."""
        code = func_ctx.code
        file_path = func_ctx.file_path
        if self.config.flow_analysis:
            try:
                cfg_builder = CFGBuilder()
                func_ctx.cfg = cfg_builder.build(code)
            except (ValueError, TypeError, AttributeError):
                logger.debug("CFG build failed for %s", func_ctx.name, exc_info=True)
        if self.config.type_inference:
            try:
                func_ctx.type_env = cast(
                    "TypeEnvironment | None", self.type_analyzer.analyze_function(code, file_path)
                )
            except (ValueError, TypeError, AttributeError):
                logger.debug("Type inference failed for %s", func_ctx.name, exc_info=True)
                func_ctx.type_env = TypeEnvironment()
        if self.config.pattern_recognition:
            try:
                func_ctx.patterns = cast(
                    "list[PatternMatch]",
                    self.pattern_analyzer.analyze_function(
                        code,
                    ),
                )
            except (ValueError, TypeError, AttributeError):
                logger.debug("Pattern recognition failed for %s", func_ctx.name, exc_info=True)
        try:
            context = DetectionContext(
                code=code,
                file_path=file_path,
                type_env=func_ctx.type_env or TypeEnvironment(),
                patterns=func_ctx.patterns,
                cfg=func_ctx.cfg,
                imports=module_ctx.imports,
                global_types=module_ctx.global_types,
            )
            raw_issues = cast("list[Issue]", self.enhanced_analyzer.analyze_with_context(context))
            issues = self._filter_issues(raw_issues, func_ctx.patterns)
            for issue in issues:
                if not self._is_duplicate(issue, builder.issues):
                    builder.add_issue(issue)
        except (RuntimeError, TypeError, ValueError, AttributeError) as e:
            builder.add_warning(f"Detection error in {func_ctx.name}: {e}")
        if self.config.taint_analysis:
            try:
                violations = self.taint_checker.check_function(code, file_path)
                for v in violations:
                    builder.add_taint_violation(v)
            except (RuntimeError, TypeError, ValueError):
                logger.debug("Taint analysis failed for %s", func_ctx.name, exc_info=True)
        if self.config.abstract_interpretation:
            try:
                warnings = self.abstract_analyzer.analyze_function(code, file_path)
                for warning in warnings:
                    if isinstance(warning, DivisionByZeroWarning):
                        if warning.confidence in ("definite", "possible"):
                            issue = Issue(
                                kind=IssueKind.DIVISION_BY_ZERO,
                                severity=(
                                    Severity.CRITICAL
                                    if warning.confidence == "definite"
                                    else Severity.HIGH
                                ),
                                message=(
                                    f"Division by zero: {warning.variable} "
                                    f"({warning.confidence})"
                                ),
                                file=file_path,
                                line=warning.line,
                                pc=warning.pc,
                                confidence=1.0 if warning.confidence == "definite" else 0.7,
                            )
                            if not self._is_duplicate(issue, builder.issues):
                                builder.add_issue(issue)
            except (RuntimeError, TypeError, ValueError):
                logger.debug(
                    "Abstract interpretation failed for %s",
                    func_ctx.name,
                    exc_info=True,
                )

    def _filter_issues(
        self,
        issues: list[Issue],
        patterns: list[PatternMatch],
    ) -> list[Issue]:
        """Filter issues based on patterns and config."""
        filtered: list[Issue] = []
        pattern_kinds = {(p.kind, p.line) for p in patterns}
        for issue in issues:
            if issue.confidence < self.config.min_confidence:
                continue
            if issue.severity == Severity.INFO and not self.config.include_info:
                continue
            should_suppress = False
            if (
                self.config.suppress_dict_int_key
                and issue.kind == IssueKind.TYPE_ERROR
                and "dict" in issue.message.lower()
                and (PatternKind.DICT_INT_KEY, issue.line) in pattern_kinds
            ):
                should_suppress = True
            if (
                self.config.suppress_defaultdict
                and issue.kind == IssueKind.KEY_ERROR
                and (PatternKind.DEFAULTDICT_ACCESS, issue.line) in pattern_kinds
            ):
                should_suppress = True
            if (
                self.config.suppress_counter
                and issue.kind == IssueKind.KEY_ERROR
                and (PatternKind.COUNTER_ACCESS, issue.line) in pattern_kinds
            ):
                should_suppress = True
            if (
                self.config.suppress_safe_iteration
                and issue.kind == IssueKind.INDEX_ERROR
                and (PatternKind.ENUMERATE_ITER, issue.line) in pattern_kinds
            ):
                should_suppress = True
            if not should_suppress:
                filtered.append(issue)
        return filtered[: self.config.max_issues_per_file]

    def _is_duplicate(self, issue: Issue, existing: list[Issue]) -> bool:
        """Check if issue is a duplicate."""
        for existing_issue in existing:
            if (
                existing_issue.kind == issue.kind
                and existing_issue.line == issue.line
                and existing_issue.file == issue.file
            ):
                return True
        return False

    def analyze_directory(
        self,
        directory: str,
        recursive: bool = True,
        exclude_patterns: list[str] | None = None,
    ) -> dict[str, AnalysisResult]:
        """Analyze all Python files in a directory."""
        results: dict[str, AnalysisResult] = {}
        exclude = set(exclude_patterns or [])
        default_exclude = {
            "__pycache__",
            ".git",
            ".venv",
            "venv",
            "env",
            "node_modules",
            "build",
            "dist",
            ".eggs",
        }
        exclude.update(default_exclude)
        path = Path(directory)
        if recursive:
            files = path.rglob("*.py")
        else:
            files = path.glob("*.py")
        for py_file in files:
            if any(part in exclude for part in py_file.parts):
                continue
            file_path = str(py_file.absolute())
            results[file_path] = self.analyze_file(file_path)
        return results


class ReportGenerator:
    """Generate analysis reports in various formats."""

    def __init__(self, results: dict[str, AnalysisResult]) -> None:
        self.results = results
        self.summary = AnalysisSummary.from_results(results)

    def generate_text(self) -> str:
        """Generate plain text report."""
        lines: list[str] = []
        lines.append("=" * 70)
        lines.append("pysymex Analysis Report")
        lines.append("=" * 70)
        lines.append("")
        lines.append("SUMMARY")
        lines.append("-" * 40)
        lines.append(f"Files analyzed: {self.summary.total_files}")
        lines.append(f"Total lines: {self.summary.total_lines}")
        lines.append(f"Functions analyzed: {self.summary.total_functions}")
        lines.append(f"Analysis time: {self.summary.total_analysis_time:.2f}s")
        lines.append("")
        lines.append(f"Total issues: {self.summary.total_issues}")
        lines.append(f"  Critical: {self.summary.critical_count}")
        lines.append(f"  High: {self.summary.high_count}")
        lines.append(f"  Medium: {self.summary.medium_count}")
        lines.append(f"  Low: {self.summary.low_count}")
        lines.append(f"  Info: {self.summary.info_count}")
        lines.append("")
        lines.append(f"Taint violations: {self.summary.total_taint_violations}")
        lines.append("")
        if self.summary.by_kind:
            lines.append("ISSUES BY TYPE")
            lines.append("-" * 40)
            for kind, count in sorted(
                self.summary.by_kind.items(), key=lambda x: x[1], reverse=True
            ):
                lines.append(f"  {kind.name}: {count}")
            lines.append("")
        lines.append("DETAILED FINDINGS")
        lines.append("-" * 40)
        for file_path, result in sorted(self.results.items()):
            if not result.has_issues():
                continue
            lines.append("")
            lines.append(f"File: {file_path}")
            lines.append(f"  Issues: {len(result.issues)}")
            for issue in result.issues:
                severity_symbol = {
                    Severity.CRITICAL: "🔴",
                    Severity.HIGH: "🟠",
                    Severity.MEDIUM: "🟡",
                    Severity.LOW: "🔵",
                    Severity.INFO: "⚪",
                }.get(issue.severity, "  ")
                lines.append(
                    f"  {severity_symbol} Line {issue.line}: "
                    f"[{issue.kind.name}] {issue.message}"
                )
            for violation in result.taint_violations:
                lines.append(
                    f"  🔒 Line {violation.sink_line}: "
                    f"[TAINT] {violation.sink.kind.name} - "
                    f"{violation.source.source}"
                )
        lines.append("")
        lines.append("=" * 70)
        return "\n".join(lines)

    def generate_json(self) -> str:
        """Generate JSON report."""
        import json

        data: dict[str, object] = {
            "summary": {
                "total_files": self.summary.total_files,
                "total_issues": self.summary.total_issues,
                "total_taint_violations": self.summary.total_taint_violations,
                "severity_counts": {
                    "critical": self.summary.critical_count,
                    "high": self.summary.high_count,
                    "medium": self.summary.medium_count,
                    "low": self.summary.low_count,
                    "info": self.summary.info_count,
                },
                "analysis_time": self.summary.total_analysis_time,
                "lines_analyzed": self.summary.total_lines,
                "functions_analyzed": self.summary.total_functions,
            },
            "files": {},
        }
        for file_path, result in self.results.items():
            file_data = {
                "issues": [
                    {
                        "kind": issue.kind.name,
                        "severity": issue.severity.name,
                        "message": issue.message,
                        "line": issue.line,
                        "column": issue.column,
                        "confidence": issue.confidence,
                    }
                    for issue in result.issues
                ],
                "taint_violations": [
                    {
                        "sink_kind": v.sink.kind.name,
                        "source": v.source.source,
                        "line": v.sink_line,
                        "severity": v.sink.severity,
                    }
                    for v in result.taint_violations
                ],
                "analysis_time": result.analysis_time,
                "lines": result.lines_of_code,
                "functions": result.functions_analyzed,
            }
            data["files"][file_path] = file_data
        return json.dumps(data, indent=2)

    def generate_sarif(self) -> str:
        """Generate SARIF format for IDE integration."""
        import json

        sarif: dict[str, object] = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "pysymex",
                            "version": "0.3.0a0",
                            "informationUri": "https://github.com/darkoss1/pysymex",
                            "rules": self._get_sarif_rules(),
                        }
                    },
                    "results": self._get_sarif_results(),
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    def _get_sarif_rules(self) -> list[dict[str, object]]:
        """Get SARIF rule definitions."""
        rules: list[dict[str, object]] = []
        for kind in IssueKind:
            rules.append(
                {
                    "id": kind.name,
                    "name": kind.name.replace("_", " ").title(),
                    "shortDescription": {
                        "text": f"Potential {kind.name.lower().replace('_', ' ')}",
                    },
                }
            )
        return rules

    def _get_sarif_results(self) -> list[dict[str, object]]:
        """Get SARIF results."""
        results: list[dict[str, object]] = []
        for file_path, result in self.results.items():
            for issue in result.issues:
                results.append(
                    {
                        "ruleId": issue.kind.name,
                        "level": {
                            Severity.CRITICAL: "error",
                            Severity.HIGH: "error",
                            Severity.MEDIUM: "warning",
                            Severity.LOW: "note",
                            Severity.INFO: "note",
                        }.get(issue.severity, "warning"),
                        "message": {
                            "text": issue.message,
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": file_path,
                                    },
                                    "region": {
                                        "startLine": issue.line,
                                        "startColumn": issue.column or 1,
                                    },
                                },
                            }
                        ],
                    }
                )
        return results
