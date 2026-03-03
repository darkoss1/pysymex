"""
Scanner Integration Types for pysymex.
Type definitions used by the scanner integration pipeline.
"""

from __future__ import annotations


from dataclasses import dataclass, field

from enum import Enum, auto

from typing import Any


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

    issues: list[Issue] = field(default_factory=list[Issue])

    taint_violations: list[TaintViolation] = field(default_factory=list[TaintViolation])

    warnings: list[Any] = field(default_factory=list[Any])

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

    patterns: list[PatternMatch] = field(default_factory=list[PatternMatch])

    parent: FunctionContext | None = None


@dataclass
class ModuleContext:
    """Context for analyzing a module."""

    file_path: str

    module_name: str

    source_code: str

    code: Any | None = None

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
