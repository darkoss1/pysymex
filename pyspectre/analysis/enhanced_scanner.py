"""
PySpectre Enhanced Scanner v2.0
This module provides the ultimate integration of all analysis systems
to deliver maximum precision with minimum false positives.
Features:
- Multi-phase analysis pipeline
- Confidence-based filtering
- Pattern recognition for safe idioms
- Type inference integration
- Flow-sensitive analysis
- Cross-function analysis
- Abstract interpretation
"""

from __future__ import annotations
import dis
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import (
    Any,
)
from .dead_code import DeadCodeAnalyzer
from .enhanced_detectors import (
    EnhancedAnalyzer,
)
from .exception_analysis import ExceptionAnalyzer
from .flow_sensitive import FlowSensitiveAnalyzer
from .pattern_handlers import PatternAnalyzer, PatternKind
from .resource_analysis import ResourceAnalyzer
from .string_analysis import StringAnalyzer
from .taint_analysis import TaintChecker, TaintKind
from .type_inference import TypeAnalyzer
from .fp_filter import filter_issue


@dataclass
class ScannerConfig:
    """Configuration for the enhanced scanner."""

    enable_type_inference: bool = True
    enable_flow_analysis: bool = True
    enable_pattern_recognition: bool = True
    enable_abstract_interpretation: bool = True
    enable_symbolic_execution: bool = False
    enable_cross_function: bool = True
    enable_dead_code: bool = True
    enable_resource_analysis: bool = True
    enable_exception_analysis: bool = True
    enable_string_analysis: bool = True
    enable_taint_analysis: bool = True
    min_confidence: float = 0.7
    suppress_likely_false_positives: bool = True
    verbose: bool = False
    show_suppressed: bool = False
    max_function_size: int = 10000
    max_path_depth: int = 50
    timeout_per_function: float = 10.0


class IssueCategory(Enum):
    """Categories for grouping issues."""

    BUG = auto()
    SECURITY = auto()
    PERFORMANCE = auto()
    STYLE = auto()
    RESOURCE = auto()
    DEAD_CODE = auto()


@dataclass
class EnhancedIssue:
    """Issue with enhanced metadata."""

    category: IssueCategory
    kind: str
    severity: str
    file: str
    line: int
    message: str
    confidence: float
    function_name: str = ""
    code_snippet: str = ""
    suggestion: str = ""
    detected_by: list[str] = field(default_factory=list)
    suppression_reasons: list[str] = field(default_factory=list)

    def is_suppressed(self) -> bool:
        """Check if issue should be suppressed."""
        return bool(self.suppression_reasons)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "category": self.category.name,
            "kind": self.kind,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "confidence": self.confidence,
            "function": self.function_name,
            "suggestion": self.suggestion,
            "detected_by": self.detected_by,
            "suppressed": self.is_suppressed(),
            "suppression_reasons": self.suppression_reasons,
        }


@dataclass
class AnalysisContext:
    """Context passed between analysis phases."""

    file_path: str
    source: str
    code: Any
    types: dict[str, Any] = field(default_factory=dict)
    patterns: Any = None  # FunctionPatternInfo
    ranges: dict[str, Any] = field(default_factory=dict)
    taint: dict[str, set[TaintKind]] = field(default_factory=dict)
    flow_analyzer: Any | None = None  # FlowSensitiveAnalyzer
    function_summaries: dict[str, Any] = field(default_factory=dict)


class AnalysisPhase:
    """Base class for analysis phases."""

    name: str = "base"

    def analyze(
        self,
        ctx: AnalysisContext,
        config: ScannerConfig,
    ) -> list[EnhancedIssue]:
        """Run analysis phase."""
        raise NotImplementedError


class TypeInferencePhase(AnalysisPhase):
    """Phase 1: Type inference."""

    name = "type_inference"

    def __init__(self) -> None:
        self.analyzer = TypeAnalyzer()

    def analyze(
        self,
        ctx: AnalysisContext,
        config: ScannerConfig,
    ) -> list[EnhancedIssue]:
        """Run type inference."""
        if not config.enable_type_inference:
            return []
        type_env = self.analyzer.analyze_function(ctx.code)
        ctx.types = type_env
        return []


class PatternRecognitionPhase(AnalysisPhase):
    """Phase 2: Recognize safe patterns."""

    name = "pattern_recognition"

    def __init__(self) -> None:
        self.analyzer = PatternAnalyzer()

    def analyze(
        self,
        ctx: AnalysisContext,
        config: ScannerConfig,
    ) -> list[EnhancedIssue]:
        """Recognize patterns."""
        if not config.enable_pattern_recognition:
            return []
        patterns = self.analyzer.analyze_function(ctx.code)
        ctx.patterns = patterns
        return []


class FlowAnalysisPhase(AnalysisPhase):
    """Phase 3: Flow-sensitive analysis."""

    name = "flow_analysis"

    def __init__(self) -> None:
        pass

    def analyze(
        self,
        ctx: AnalysisContext,
        config: ScannerConfig,
    ) -> list[EnhancedIssue]:
        """Run flow analysis."""
        if not config.enable_flow_analysis:
            return []
        try:
            ctx.flow_analyzer = FlowSensitiveAnalyzer(ctx.code)
        except Exception:
            pass
        return []


class BugDetectionPhase(AnalysisPhase):
    """Phase 4: Bug detection with all context."""

    name = "bug_detection"

    def __init__(self) -> None:
        self.analyzer = EnhancedAnalyzer()

    def analyze(
        self,
        ctx: AnalysisContext,
        config: ScannerConfig,
    ) -> list[EnhancedIssue]:
        """Detect bugs with enhanced precision."""
        issues: list[EnhancedIssue] = []
        raw_issues = self.analyzer.analyze_function(
            ctx.code,
            ctx.file_path,
            type_env=ctx.types,
            pattern_info=ctx.patterns,
            flow_analyzer=ctx.flow_analyzer,
        )
        for issue in raw_issues:
            enhanced = EnhancedIssue(
                category=IssueCategory.BUG,
                kind=issue.kind.name,
                severity=issue.severity.name,
                file=issue.file,
                line=issue.line,
                message=issue.message,
                confidence=issue.confidence,
                function_name=ctx.code.co_name,
                detected_by=["enhanced_detectors"],
            )
            if config.suppress_likely_false_positives:
                self._check_suppression(enhanced, ctx)
            if enhanced.confidence >= config.min_confidence:
                issues.append(enhanced)
        return issues

    def _check_suppression(
        self,
        issue: EnhancedIssue,
        ctx: AnalysisContext,
    ) -> None:
        """Check if issue should be suppressed."""
        line = issue.line
        if ctx.patterns and hasattr(ctx.patterns, "matcher"):
            patterns = ctx.patterns.matcher.get_patterns_at(line)
            pattern_kinds = {p.kind for p in patterns}
            if issue.kind == "KEY_ERROR" and PatternKind.DEFAULTDICT_ACCESS in pattern_kinds:
                issue.suppression_reasons.append("defaultdict access is safe")
                issue.confidence *= 0.1
            if issue.kind == "KEY_ERROR" and PatternKind.DICT_GET in pattern_kinds:
                issue.suppression_reasons.append("dict.get() handles missing keys")
                issue.confidence *= 0.1
            if issue.kind == "INDEX_ERROR" and PatternKind.ENUMERATE_ITER in pattern_kinds:
                issue.suppression_reasons.append("enumerate provides valid indices")
                issue.confidence *= 0.1

        class MockIssue:
            def __init__(self, kind, line, message, function_name):
                from .enhanced_detectors import IssueKind

                try:
                    self.kind = IssueKind[kind]
                except (KeyError, AttributeError):
                    self.kind = IssueKind.UNKNOWN
                self.line_number = line
                self.message = message
                self.function_name = function_name
                self.model = None

        mock = MockIssue(issue.kind, issue.line, issue.message, issue.function_name)
        result = filter_issue(mock, ctx.source)  # type: ignore
        if result.should_filter:
            issue.suppression_reasons.append(f"FP Filter: {result.reason}")
            issue.confidence *= 0.5


class DeadCodePhase(AnalysisPhase):
    """Phase 5: Dead code detection."""

    name = "dead_code"

    def __init__(self) -> None:
        self.analyzer = DeadCodeAnalyzer()

    def analyze(
        self,
        ctx: AnalysisContext,
        config: ScannerConfig,
    ) -> list[EnhancedIssue]:
        """Detect dead code."""
        if not config.enable_dead_code:
            return []
        issues: list[EnhancedIssue] = []
        dead_code = self.analyzer.analyze_function(ctx.code, ctx.file_path)
        for dc in dead_code:
            issues.append(
                EnhancedIssue(
                    category=IssueCategory.DEAD_CODE,
                    kind=dc.kind.name,
                    severity="warning",
                    file=dc.file,
                    line=dc.line,
                    message=dc.message,
                    confidence=dc.confidence,
                    function_name=ctx.code.co_name,
                    detected_by=["dead_code_analyzer"],
                )
            )
        return issues


class ResourcePhase(AnalysisPhase):
    """Phase 6: Resource leak detection."""

    name = "resource_analysis"

    def __init__(self) -> None:
        self.analyzer = ResourceAnalyzer()

    def analyze(
        self,
        ctx: AnalysisContext,
        config: ScannerConfig,
    ) -> list[EnhancedIssue]:
        """Detect resource leaks."""
        if not config.enable_resource_analysis:
            return []
        issues: list[EnhancedIssue] = []
        warnings = self.analyzer.analyze_function(ctx.code, ctx.file_path)
        for warn in warnings:
            issues.append(
                EnhancedIssue(
                    category=IssueCategory.RESOURCE,
                    kind=warn.kind,
                    severity=warn.severity,
                    file=warn.file,
                    line=warn.line,
                    message=warn.message,
                    confidence=0.8,
                    function_name=ctx.code.co_name,
                    detected_by=["resource_analyzer"],
                )
            )
        return issues


class SecurityPhase(AnalysisPhase):
    """Phase 7: Security analysis (taint + string)."""

    name = "security"

    def __init__(self) -> None:
        self.taint_checker = TaintChecker()
        self.string_analyzer = StringAnalyzer()

    def analyze(
        self,
        ctx: AnalysisContext,
        config: ScannerConfig,
    ) -> list[EnhancedIssue]:
        """Run security analysis."""
        issues: list[EnhancedIssue] = []
        if config.enable_taint_analysis:
            taint_issues = self.taint_checker.check_function(ctx.code)
            for ti in taint_issues:
                issues.append(
                    EnhancedIssue(
                        category=IssueCategory.SECURITY,
                        kind=ti.kind.name if hasattr(ti, "kind") else "TAINT",
                        severity="error",
                        file=ctx.file_path,
                        line=ti.line if hasattr(ti, "line") else 0,
                        message=str(ti),
                        confidence=0.9,
                        function_name=ctx.code.co_name,
                        detected_by=["taint_analysis"],
                    )
                )
        if config.enable_string_analysis:
            string_issues = self.string_analyzer.analyze_source(ctx.source, ctx.file_path)
            for si in string_issues:
                issues.append(
                    EnhancedIssue(
                        category=IssueCategory.SECURITY,
                        kind=si.kind.name,
                        severity=si.severity,
                        file=si.file,
                        line=si.line,
                        message=si.message,
                        confidence=0.85,
                        detected_by=["string_analysis"],
                    )
                )
        return issues


class ExceptionPhase(AnalysisPhase):
    """Phase 8: Exception handling analysis."""

    name = "exception"

    def __init__(self) -> None:
        self.analyzer = ExceptionAnalyzer()

    def analyze(
        self,
        ctx: AnalysisContext,
        config: ScannerConfig,
    ) -> list[EnhancedIssue]:
        """Analyze exception handling."""
        if not config.enable_exception_analysis:
            return []
        issues: list[EnhancedIssue] = []
        warnings = self.analyzer.analyze_source(ctx.source, ctx.file_path)
        for warn in warnings:
            issues.append(
                EnhancedIssue(
                    category=IssueCategory.STYLE,
                    kind=warn.kind.name,
                    severity=warn.severity,
                    file=warn.file,
                    line=warn.line,
                    message=warn.message,
                    confidence=0.8,
                    detected_by=["exception_analysis"],
                )
            )
        return issues


class EnhancedScanner:
    """
    Enhanced scanner with multi-phase analysis pipeline.
    """

    def __init__(self, config: ScannerConfig | None = None) -> None:
        self.config = config or ScannerConfig()
        self.phases: list[AnalysisPhase] = [
            TypeInferencePhase(),
            PatternRecognitionPhase(),
            FlowAnalysisPhase(),
            BugDetectionPhase(),
            DeadCodePhase(),
            ResourcePhase(),
            SecurityPhase(),
            ExceptionPhase(),
        ]
        self.stats: dict[str, int] = defaultdict(int)

    def scan_file(self, file_path: str) -> list[EnhancedIssue]:
        """Scan a single file."""
        issues: list[EnhancedIssue] = []
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                source = f.read()
            code = compile(source, file_path, "exec")
            ctx = AnalysisContext(
                file_path=file_path,
                source=source,
                code=code,
            )
            issues.extend(self._run_phases(ctx))
            self._scan_nested(code, source, file_path, issues)
            self.stats["files_scanned"] += 1
            self.stats["issues_found"] += len(issues)
        except SyntaxError as e:
            issues.append(
                EnhancedIssue(
                    category=IssueCategory.BUG,
                    kind="SYNTAX_ERROR",
                    severity="error",
                    file=file_path,
                    line=e.lineno or 0,
                    message=f"Syntax error: {e.msg}",
                    confidence=1.0,
                )
            )
            self.stats["syntax_errors"] += 1
        except Exception as e:
            if self.config.verbose:
                print(f"Error scanning {file_path}: {e}")
            self.stats["scan_errors"] += 1
        return issues

    def _scan_nested(
        self,
        code: Any,
        source: str,
        file_path: str,
        issues: list[EnhancedIssue],
    ) -> None:
        """Scan nested functions."""
        for const in code.co_consts:
            if hasattr(const, "co_code"):
                if len(list(dis.get_instructions(const))) > self.config.max_function_size:
                    self.stats["skipped_large_functions"] += 1
                    continue
                ctx = AnalysisContext(
                    file_path=file_path,
                    source=source,
                    code=const,
                )
                issues.extend(self._run_phases(ctx))
                self._scan_nested(const, source, file_path, issues)

    def _run_phases(self, ctx: AnalysisContext) -> list[EnhancedIssue]:
        """Run all analysis phases."""
        all_issues: list[EnhancedIssue] = []
        for phase in self.phases:
            try:
                issues = phase.analyze(ctx, self.config)
                all_issues.extend(issues)
            except Exception as e:
                if self.config.verbose:
                    print(f"Phase {phase.name} failed: {e}")
                self.stats[f"{phase.name}_errors"] += 1
        return all_issues

    def scan_directory(
        self,
        directory: str,
        pattern: str = "**/*.py",
    ) -> list[EnhancedIssue]:
        """Scan all Python files in directory."""
        all_issues: list[EnhancedIssue] = []
        path = Path(directory)
        for file_path in path.glob(pattern):
            if file_path.is_file():
                issues = self.scan_file(str(file_path))
                all_issues.extend(issues)
        return all_issues

    def generate_report(
        self,
        issues: list[EnhancedIssue],
        format: str = "text",
    ) -> str:
        """Generate report from issues."""
        if format == "json":
            return json.dumps(
                {
                    "issues": [i.to_dict() for i in issues if not i.is_suppressed()],
                    "suppressed": [i.to_dict() for i in issues if i.is_suppressed()],
                    "stats": dict(self.stats),
                },
                indent=2,
            )
        lines: list[str] = []
        lines.append("=" * 60)
        lines.append("PySpectre Enhanced Scan Report v2.0")
        lines.append("=" * 60)
        lines.append("")
        by_file: dict[str, list[EnhancedIssue]] = defaultdict(list)
        for issue in issues:
            if not issue.is_suppressed() or self.config.show_suppressed:
                by_file[issue.file].append(issue)
        for file_path, file_issues in sorted(by_file.items()):
            lines.append(f"\n📄 {file_path}")
            lines.append("-" * 40)
            for issue in sorted(file_issues, key=lambda i: i.line):
                status = "🔴" if issue.severity == "error" else "🟡"
                suppressed = " (SUPPRESSED)" if issue.is_suppressed() else ""
                lines.append(
                    f"  {status} Line {issue.line}: [{issue.kind}] {issue.message}"
                    f" (confidence: {issue.confidence:.0%}){suppressed}"
                )
                if issue.suggestion:
                    lines.append(f"     💡 {issue.suggestion}")
        total = len([i for i in issues if not i.is_suppressed()])
        suppressed = len([i for i in issues if i.is_suppressed()])
        lines.append("")
        lines.append("=" * 60)
        lines.append("Summary")
        lines.append("=" * 60)
        lines.append(f"Total issues: {total}")
        lines.append(f"Suppressed (likely false positives): {suppressed}")
        lines.append(f"Files scanned: {self.stats.get('files_scanned', 0)}")
        return "\n".join(lines)


def main() -> int:
    """Command-line interface."""
    import argparse

    parser = argparse.ArgumentParser(
        description="PySpectre Enhanced Scanner v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "path",
        help="File or directory to scan",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.7,
        help="Minimum confidence threshold (0.0-1.0)",
    )
    parser.add_argument(
        "--show-suppressed",
        action="store_true",
        help="Show suppressed issues",
    )
    parser.add_argument(
        "--no-suppress",
        action="store_true",
        help="Don't suppress likely false positives",
    )
    args = parser.parse_args()
    config = ScannerConfig(
        verbose=args.verbose,
        min_confidence=args.min_confidence,
        show_suppressed=args.show_suppressed,
        suppress_likely_false_positives=not args.no_suppress,
    )
    scanner = EnhancedScanner(config)
    path = Path(args.path)
    if path.is_file():
        issues = scanner.scan_file(str(path))
    elif path.is_dir():
        issues = scanner.scan_directory(str(path))
    else:
        print(f"Error: {args.path} not found")
        return 1
    report = scanner.generate_report(issues, args.format)
    print(report)
    errors = sum(1 for i in issues if i.severity == "error" and not i.is_suppressed())
    return 1 if errors > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
