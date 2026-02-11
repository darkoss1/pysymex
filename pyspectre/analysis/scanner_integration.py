"""
Scanner Integration Module for PySpectre.
This module integrates all the new analysis components with the
main scanning pipeline, providing a unified interface for:
- Type inference
- Flow-sensitive analysis
- Pattern recognition
- Taint analysis
- Abstract interpretation
- Enhanced detectors
This creates a comprehensive static analysis pipeline that minimizes
false positives while maximizing bug detection.
"""

from __future__ import annotations
import dis
import os
import sys
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import (
    Any,
)
from .abstract_interpreter import (
    AbstractAnalyzer,
    DivisionByZeroWarning,
)
from .enhanced_detectors import (
    DetectionContext,
    EnhancedAnalyzer,
    Issue,
    IssueKind,
    Severity,
)
from .flow_sensitive import (
    CFGBuilder,
    ControlFlowGraph,
    FlowSensitiveAnalyzer,
)
from .function_models import (
    FunctionSummarizer,
)
from .pattern_handlers import (
    PatternAnalyzer,
    PatternKind,
    PatternMatch,
)
from .taint_analysis import (
    TaintChecker,
    TaintViolation,
)
from .type_inference import (
    PyType,
    TypeAnalyzer,
    TypeEnvironment,
)


@dataclass
class AnalysisConfig:
    """Configuration for the analysis pipeline."""

    type_inference: bool = True
    flow_analysis: bool = True
    pattern_recognition: bool = True
    taint_analysis: bool = True
    abstract_interpretation: bool = True
    context_sensitivity: int = 2
    path_sensitivity: bool = True
    suppress_dict_int_key: bool = True
    suppress_defaultdict: bool = True
    suppress_counter: bool = True
    suppress_safe_iteration: bool = True
    min_confidence: float = 0.5
    report_uncertain: bool = False
    max_issues_per_file: int = 100
    include_info: bool = False
    timeout_per_function: float = 5.0
    max_iterations: int = 1000


@dataclass
class AnalysisResult:
    """Result of analyzing a single file."""

    file_path: str
    issues: list[Issue] = field(default_factory=list)
    taint_violations: list[TaintViolation] = field(default_factory=list)
    warnings: list[Any] = field(default_factory=list)
    analysis_time: float = 0.0
    functions_analyzed: int = 0
    lines_of_code: int = 0
    suppressed_count: int = 0

    def has_issues(self) -> bool:
        """Check if any issues were found."""
        return bool(self.issues or self.taint_violations)

    def critical_count(self) -> int:
        """Count critical severity issues."""
        return sum(1 for i in self.issues if i.severity == Severity.CRITICAL)

    def high_count(self) -> int:
        """Count high severity issues."""
        return sum(1 for i in self.issues if i.severity == Severity.HIGH)

    def total_count(self) -> int:
        """Total issue count."""
        return len(self.issues) + len(self.taint_violations)


@dataclass
class FunctionContext:
    """Context for analyzing a single function."""

    code: Any
    name: str
    file_path: str
    module_name: str
    cfg: ControlFlowGraph | None = None
    type_env: TypeEnvironment | None = None
    patterns: list[PatternMatch] = field(default_factory=list)
    parent: FunctionContext | None = None


@dataclass
class ModuleContext:
    """Context for analyzing a module."""

    file_path: str
    module_name: str
    source_code: str
    code: Any | None = None
    functions: dict[str, FunctionContext] = field(default_factory=dict)
    imports: set[str] = field(default_factory=set)
    global_types: dict[str, PyType] = field(default_factory=dict)


class AnalysisPipeline:
    """
    Main analysis pipeline integrating all analysis components.
    """

    def __init__(self, config: AnalysisConfig | None = None) -> None:
        self.config = config or AnalysisConfig()
        self.type_analyzer = TypeAnalyzer()
        self.flow_analyzer = FlowSensitiveAnalyzer()
        self.pattern_analyzer = PatternAnalyzer()
        self.taint_checker = TaintChecker()
        self.abstract_analyzer = AbstractAnalyzer()
        self.enhanced_analyzer = EnhancedAnalyzer()
        self.function_models = FunctionSummarizer()
        self._setup_patterns()

    def _setup_patterns(self) -> None:
        """Set up pattern recognizers."""

    def analyze_file(self, file_path: str) -> AnalysisResult:
        """Analyze a single Python file."""
        result = AnalysisResult(file_path=file_path)
        start_time = time.time()
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                source = f.read()
            result.lines_of_code = len(source.splitlines())
            code = compile(source, file_path, "exec")
            module_name = Path(file_path).stem
            module_ctx = ModuleContext(
                file_path=file_path,
                module_name=module_name,
                source_code=source,
                code=code,
            )
            self._analyze_module(module_ctx, result)
        except SyntaxError as e:
            result.issues.append(
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
        except Exception as e:
            result.warnings.append(f"Analysis error: {type(e).__name__}: {e}")
        result.analysis_time = time.time() - start_time
        return result

    def _analyze_module(
        self,
        module_ctx: ModuleContext,
        result: AnalysisResult,
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
        self._analyze_function(module_func_ctx, module_ctx, result)
        result.functions_analyzed += 1
        self._find_functions(module_ctx.code, module_ctx, result)

    def _extract_imports(self, module_ctx: ModuleContext) -> None:
        """Extract import information from the module."""
        if not module_ctx.code:
            return
        for const in module_ctx.code.co_consts:
            if isinstance(const, str):
                module_ctx.imports.add(const)
        for instr in dis.get_instructions(module_ctx.code):
            if instr.opname == "IMPORT_NAME":
                module_ctx.imports.add(str(instr.argval))

    def _find_functions(
        self,
        code: Any,
        module_ctx: ModuleContext,
        result: AnalysisResult,
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
                self._analyze_function(func_ctx, module_ctx, result)
                result.functions_analyzed += 1
                self._find_functions(const, module_ctx, result, func_ctx)

    def _analyze_function(
        self,
        func_ctx: FunctionContext,
        module_ctx: ModuleContext,
        result: AnalysisResult,
    ) -> None:
        """Run all analysis phases on a function."""
        code = func_ctx.code
        file_path = func_ctx.file_path
        if self.config.flow_analysis:
            try:
                builder = CFGBuilder()
                func_ctx.cfg = builder.build(code)
            except Exception:
                pass
        if self.config.type_inference:
            try:
                func_ctx.type_env = self.type_analyzer.analyze_function(code, file_path)
            except Exception:
                func_ctx.type_env = TypeEnvironment()
        if self.config.pattern_recognition:
            try:
                func_ctx.patterns = self.pattern_analyzer.analyze_function(code, file_path)
            except Exception:
                pass
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
            issues = self.enhanced_analyzer.analyze_with_context(context)
            issues = self._filter_issues(issues, func_ctx.patterns)
            result.issues.extend(issues)
        except Exception as e:
            result.warnings.append(f"Detection error in {func_ctx.name}: {e}")
        if self.config.taint_analysis:
            try:
                violations = self.taint_checker.check_function(code, file_path)
                result.taint_violations.extend(violations)
            except Exception:
                pass
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
                            if not self._is_duplicate(issue, result.issues):
                                result.issues.append(issue)
            except Exception:
                pass

    def _filter_issues(
        self,
        issues: list[Issue],
        patterns: list[PatternMatch],
    ) -> list[Issue]:
        """Filter issues based on patterns and config."""
        filtered = []
        pattern_lines = {p.line for p in patterns}
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


class ReportFormat(Enum):
    """Output format for analysis reports."""

    TEXT = auto()
    JSON = auto()
    HTML = auto()
    SARIF = auto()


@dataclass
class AnalysisSummary:
    """Summary of analysis across all files."""

    total_files: int = 0
    total_issues: int = 0
    total_taint_violations: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    total_analysis_time: float = 0.0
    total_lines: int = 0
    total_functions: int = 0
    files_with_issues: int = 0
    by_kind: dict[IssueKind, int] = field(default_factory=dict)

    @classmethod
    def from_results(cls, results: dict[str, AnalysisResult]) -> AnalysisSummary:
        """Create summary from analysis results."""
        summary = cls()
        summary.total_files = len(results)
        for result in results.values():
            summary.total_issues += len(result.issues)
            summary.total_taint_violations += len(result.taint_violations)
            summary.total_analysis_time += result.analysis_time
            summary.total_lines += result.lines_of_code
            summary.total_functions += result.functions_analyzed
            if result.has_issues():
                summary.files_with_issues += 1
            for issue in result.issues:
                if issue.severity == Severity.CRITICAL:
                    summary.critical_count += 1
                elif issue.severity == Severity.HIGH:
                    summary.high_count += 1
                elif issue.severity == Severity.MEDIUM:
                    summary.medium_count += 1
                elif issue.severity == Severity.LOW:
                    summary.low_count += 1
                else:
                    summary.info_count += 1
                summary.by_kind[issue.kind] = summary.by_kind.get(issue.kind, 0) + 1
        return summary


class ReportGenerator:
    """Generate analysis reports in various formats."""

    def __init__(self, results: dict[str, AnalysisResult]) -> None:
        self.results = results
        self.summary = AnalysisSummary.from_results(results)

    def generate_text(self) -> str:
        """Generate plain text report."""
        lines = []
        lines.append("=" * 70)
        lines.append("PySpectre Analysis Report")
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

        data = {
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

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "PySpectre",
                            "version": "0.3.0a0",
                            "informationUri": "https://github.com/darkoss1/pyspecter",
                            "rules": self._get_sarif_rules(),
                        }
                    },
                    "results": self._get_sarif_results(),
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    def _get_sarif_rules(self) -> list[dict]:
        """Get SARIF rule definitions."""
        rules = []
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

    def _get_sarif_results(self) -> list[dict]:
        """Get SARIF results."""
        results = []
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


def analyze(
    target: str,
    config: AnalysisConfig | None = None,
    output_format: ReportFormat = ReportFormat.TEXT,
) -> str:
    """
    Main entry point for analysis.
    Args:
        target: File or directory to analyze
        config: Analysis configuration
        output_format: Output format for report
    Returns:
        Formatted report string
    """
    pipeline = AnalysisPipeline(config)
    if os.path.isfile(target):
        results = {target: pipeline.analyze_file(target)}
    elif os.path.isdir(target):
        results = pipeline.analyze_directory(target)
    else:
        raise ValueError(f"Target not found: {target}")
    generator = ReportGenerator(results)
    if output_format == ReportFormat.TEXT:
        return generator.generate_text()
    elif output_format == ReportFormat.JSON:
        return generator.generate_json()
    elif output_format == ReportFormat.SARIF:
        return generator.generate_sarif()
    else:
        return generator.generate_text()


def main(argv: list[str] | None = None) -> int:
    """Command-line interface."""
    import argparse

    parser = argparse.ArgumentParser(description="PySpectre Enhanced Static Analysis")
    parser.add_argument(
        "target",
        help="File or directory to analyze",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output file (default: stdout)",
    )
    parser.add_argument(
        "--no-type-inference",
        action="store_true",
        help="Disable type inference",
    )
    parser.add_argument(
        "--no-taint",
        action="store_true",
        help="Disable taint analysis",
    )
    parser.add_argument(
        "--include-info",
        action="store_true",
        help="Include info-level issues",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.5,
        help="Minimum confidence threshold (0-1)",
    )
    args = parser.parse_args(argv)
    config = AnalysisConfig(
        type_inference=not args.no_type_inference,
        taint_analysis=not args.no_taint,
        include_info=args.include_info,
        min_confidence=args.min_confidence,
    )
    format_map = {
        "text": ReportFormat.TEXT,
        "json": ReportFormat.JSON,
        "sarif": ReportFormat.SARIF,
    }
    output_format = format_map[args.format]
    try:
        report = analyze(args.target, config, output_format)
        if args.output:
            with open(args.output, "w") as f:
                f.write(report)
        else:
            print(report)
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
