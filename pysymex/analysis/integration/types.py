"""
Scanner Integration Types for pysymex.
Type definitions used by the scanner integration pipeline.
"""

from __future__ import annotations

import types
from dataclasses import dataclass, field
from enum import Enum, auto

from ..detectors.static import (
    Issue,
    IssueKind,
    Severity,
)
from ..flow_sensitive import (
    ControlFlowGraph,
)
from ..patterns import (
    PatternMatch,
)
from ..taint.checker import (
    TaintViolation,
)
from ..type_inference import (
    PyType,
    TypeEnvironment,
)


@dataclass(frozen=True, slots=True)
class AnalysisConfig:
    """Configuration for the analysis pipeline.

    Attributes:
        type_inference: Enable type inference phase.
        flow_analysis: Enable flow-sensitive analysis.
        pattern_recognition: Enable safe-pattern recognition.
        taint_analysis: Enable taint-flow analysis.
        abstract_interpretation: Enable abstract-interpretation phase.
        context_sensitivity: Call-site sensitivity depth.
        path_sensitivity: Enable path-sensitive reasoning.
        suppress_dict_int_key: Suppress dict-int-key false positives.
        suppress_defaultdict: Suppress defaultdict false positives.
        suppress_counter: Suppress Counter false positives.
        suppress_safe_iteration: Suppress safe-iteration false positives.
        min_confidence: Minimum confidence threshold for reporting.
        report_uncertain: Include uncertain issues in output.
        max_issues_per_file: Cap issues per file.
        include_info: Include INFO-severity issues.
        timeout_per_function: Analysis timeout per function (seconds).
        max_iterations: Maximum loop iterations.
    """

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
    """Result of analysing a single file.

    Attributes:
        file_path: Analysed file path.
        issues: Detected static-analysis issues.
        taint_violations: Detected taint violations.
        warnings: Non-fatal analysis warnings.
        analysis_time: Wall-clock seconds spent analysing.
        functions_analyzed: Number of functions analysed.
        lines_of_code: Total lines in the source file.
        suppressed_count: Number of issues suppressed.
    """

    file_path: str
    issues: list[Issue] = field(default_factory=list[Issue])
    taint_violations: list[TaintViolation] = field(default_factory=list[TaintViolation])
    warnings: list[object] = field(default_factory=list[object])
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


class AnalysisResultBuilder:
    """Mutable builder for :class:`AnalysisResult`.

    Internal analysis phases mutate the builder; the outermost shell
    calls :meth:`build` to produce the final ``AnalysisResult``.
    """

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.issues: list[Issue] = []
        self.taint_violations: list[TaintViolation] = []
        self.warnings: list[object] = []
        self.analysis_time: float = 0.0
        self.functions_analyzed: int = 0
        self.lines_of_code: int = 0
        self.suppressed_count: int = 0

    def add_issue(self, issue: Issue) -> AnalysisResultBuilder:
        """Add issue."""
        self.issues.append(issue)
        return self

    def add_taint_violation(self, violation: TaintViolation) -> AnalysisResultBuilder:
        """Add taint violation."""
        self.taint_violations.append(violation)
        return self

    def add_warning(self, warning: object) -> AnalysisResultBuilder:
        """Add warning."""
        self.warnings.append(warning)
        return self

    def increment_functions(self, n: int = 1) -> AnalysisResultBuilder:
        """Increment functions."""
        self.functions_analyzed += n
        return self

    def build(self) -> AnalysisResult:
        """Return a :class:`AnalysisResult` snapshot."""
        return AnalysisResult(
            file_path=self.file_path,
            issues=list(self.issues),
            taint_violations=list(self.taint_violations),
            warnings=list(self.warnings),
            analysis_time=self.analysis_time,
            functions_analyzed=self.functions_analyzed,
            lines_of_code=self.lines_of_code,
            suppressed_count=self.suppressed_count,
        )


@dataclass
class FunctionContext:
    """Context for analysing a single function.

    Attributes:
        code: Python code object.
        name: Function name.
        file_path: Source file path.
        module_name: Enclosing module name.
        cfg: Control-flow graph, if built.
        type_env: Type environment from inference.
        patterns: Recognised safe patterns.
        parent: Parent function context for nesting.
    """

    code: types.CodeType
    name: str
    file_path: str
    module_name: str
    cfg: ControlFlowGraph | None = None
    type_env: TypeEnvironment | None = None
    patterns: list[PatternMatch] = field(default_factory=list[PatternMatch])
    parent: FunctionContext | None = None


@dataclass
class ModuleContext:
    """Context for analysing a module.

    Attributes:
        file_path: Module file path.
        module_name: Module name.
        source_code: Raw source text.
        code: Compiled code object.
        functions: Discovered function contexts.
        imports: Set of imported module names.
        global_types: Inferred types for module-level names.
    """

    file_path: str
    module_name: str
    source_code: str
    code: object | None = None
    functions: dict[str, FunctionContext] = field(default_factory=dict[str, FunctionContext])
    imports: set[str] = field(default_factory=set[str])
    global_types: dict[str, PyType] = field(default_factory=dict[str, PyType])


class ReportFormat(Enum):
    """Output format for analysis reports."""

    TEXT = auto()
    JSON = auto()
    HTML = auto()
    SARIF = auto()


@dataclass
class AnalysisSummary:
    """Aggregate summary of analysis across all files.

    Attributes:
        total_files: Number of files analysed.
        total_issues: Total detected issues.
        total_taint_violations: Total taint violations.
        critical_count: Count of CRITICAL-severity issues.
        high_count: Count of HIGH-severity issues.
        medium_count: Count of MEDIUM-severity issues.
        low_count: Count of LOW-severity issues.
        info_count: Count of INFO-severity issues.
        total_analysis_time: Aggregate wall-clock time.
        total_lines: Total source lines across all files.
        total_functions: Total functions analysed.
        files_with_issues: Number of files with at least one issue.
        by_kind: Issue counts broken down by ``IssueKind``.
    """

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
    by_kind: dict[IssueKind, int] = field(default_factory=dict[IssueKind, int])

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
