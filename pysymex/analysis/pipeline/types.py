# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Enhanced scanner types, configuration, and base interfaces.

Contains the shared data structures used across the scanner pipeline:
- ScannerConfig: Scanner configuration parameters
- IssueCategory: Issue classification enum
- ScanIssue: Rich issue metadata dataclass
- AnalysisContext: Shared state passed between phases
- AnalysisPhase: Abstract base for analysis pipeline phases
- SUGGESTION_MAP: Actionable fix suggestions per issue kind
"""

from __future__ import annotations

import types
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from ..exceptions.handler import ExceptionHandlerInfo

from ..taint.checker import TaintKind

__all__ = [
    "SUGGESTION_MAP",
    "AnalysisContext",
    "AnalysisPhase",
    "IssueCategory",
    "ScanIssue",
    "ScannerConfig",
]


class NoneCheckAnalyzerLike(Protocol):
    def is_none_safe(self, var_name: str) -> bool: ...


SUGGESTION_MAP: dict[str, str] = {
    "UNUSED_VARIABLE": "Remove the variable or prefix with _ if intentionally unused",
    "UNUSED_IMPORT": "Remove the import or add to __all__ if re-exporting",
    "UNUSED_PARAMETER": "Prefix with _ to indicate intentionally unused, or remove if possible",
    "DEAD_STORE": "Remove the overwritten assignment or use the value before reassigning",
    "UNREACHABLE_CODE": "Remove the unreachable statements after return/raise",
    "REDUNDANT_CONDITION": "Simplify the condition or remove the dead branch",
    "UNUSED_FUNCTION": "Remove the function or verify it's needed for external callers",
    "UNREACHABLE_BRANCH": "Remove the dead branch or fix the condition",
    "REDUNDANT_ASSIGNMENT": "Remove the redundant assignment",
    "UNREACHABLE_HANDLER": "Remove the unreachable exception handler",
    "DIVISION_BY_ZERO": "Add a zero-check guard before the division",
    "KEY_ERROR": "Use dict.get() with a default, or check 'key in dict' first",
    "INDEX_ERROR": "Check len() before indexing, or use try/except",
    "TYPE_ERROR": "Verify argument types match the expected signature",
    "ATTRIBUTE_ERROR": "Check if the attribute exists with hasattr() or guard with isinstance()",
    "NULL_DEREFERENCE": "Add an 'is not None' check before accessing the value",
    "ASSERTION_ERROR": "Verify the assertion condition or add a descriptive message",
    "VALUE_ERROR": "Validate the value before passing it to the function",
    "INVALID_ARGUMENT": "Check argument constraints before calling",
    "INFINITE_LOOP": "Add a termination condition or break statement",
    "INFINITE_RECURSION": "Add a base case to the recursion",
    "TOO_BROAD_EXCEPT": "Catch specific exceptions instead of Exception",
    "BARE_EXCEPT": "Use 'except Exception:' instead of bare 'except:'",
    "EXCEPTION_SWALLOWED": "Log the exception or re-raise it",
    "EXCEPTION_NOT_LOGGED": "Add logging in the exception handler",
    "FINALLY_RETURN": "Avoid return in finally; it silences exceptions",
    "DUPLICATE_EXCEPT": "Remove the duplicate exception handler",
    "UNREACHABLE_EXCEPT": "Reorder handlers: specific exceptions before broad ones",
    "WRONG_EXCEPTION_ORDER": "Put more specific exception handlers first",
    "RESOURCE_LEAK": "Use a 'with' statement to ensure proper cleanup",
    "UNCLOSED_FILE": "Use a 'with' statement for file operations",
    "UNCLOSED_CONNECTION": "Use a 'with' statement or ensure close() is called",
    "TAINT": "Sanitize or validate the input before use",
    "SQL_INJECTION": "Use parameterized queries instead of string formatting",
    "COMMAND_INJECTION": "Use subprocess with a list of args instead of shell=True",
    "PATH_TRAVERSAL": "Validate and sanitize file paths before use",
    "EVAL": "Avoid eval/exec on untrusted input; use ast.literal_eval for data",
    "HARDCODED_SECRET": "Move secrets to environment variables or a secrets manager",
    "WEAK_CRYPTO": "Use a stronger cryptographic algorithm",
    "FORMAT_STRING": "Use f-strings or .format() with validated inputs",
}


@dataclass(frozen=True, slots=True)
class ScannerConfig:
    """Configuration for the enhanced scanner pipeline.

    Attributes:
        enable_type_inference: Enable type inference phase.
        enable_flow_analysis: Enable flow-sensitive analysis.
        enable_pattern_recognition: Enable pattern recognition.
        enable_abstract_interpretation: Enable abstract interpretation.
        enable_symbolic_execution: Enable symbolic execution (expensive).
        enable_cross_function: Enable cross-function analysis.
        enable_dead_code: Enable dead code detection.
        enable_resource_analysis: Enable resource leak detection.
        enable_exception_analysis: Enable exception handler analysis.
        enable_string_analysis: Enable string security analysis.
        enable_taint_analysis: Enable taint analysis.
        min_confidence: Minimum confidence for reporting issues.
        suppress_likely_false_positives: Auto-suppress likely FPs.
        verbose: Enable verbose output.
        show_suppressed: Show suppressed issues.
        max_function_size: Skip functions larger than this (bytes).
        max_path_depth: Maximum path exploration depth.
        timeout_per_function: Per-function timeout in seconds.
    """

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
    """High-level categories for grouping scan issues."""

    BUG = auto()
    SECURITY = auto()
    PERFORMANCE = auto()
    STYLE = auto()
    RESOURCE = auto()
    DEAD_CODE = auto()


@dataclass
class ScanIssue:
    """Rich issue representation with metadata for scanner output.

    Attributes:
        category: High-level issue category.
        kind: Specific issue kind string.
        severity: Severity level string.
        file: Source file path.
        line: Source line number.
        message: Human-readable description.
        confidence: Detection confidence in ``[0, 1]``.
        function_name: Enclosing function name.
        code_snippet: Relevant source snippet.
        suggestion: Actionable fix suggestion.
        detected_by: Names of detectors that found this issue.
        suppression_reasons: Reasons the issue was suppressed.
    """

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
    detected_by: list[str] = field(default_factory=list[str])
    suppression_reasons: list[str] = field(default_factory=list[str])

    def is_suppressed(self) -> bool:
        """Check if issue should be suppressed."""
        return bool(self.suppression_reasons)

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary."""
        from enum import Enum

        def _safe(v: object) -> object:
            """Safe."""
            return v.name if isinstance(v, Enum) else v

        return {
            "category": self.category.name,
            "kind": _safe(self.kind),
            "severity": _safe(self.severity),
            "file": self.file,
            "line": self.line if not isinstance(self.line, bool) else 0,
            "message": self.message,
            "confidence": self.confidence,
            "function": self.function_name,
            "suggestion": self.suggestion,
            "detected_by": self.detected_by,
            "suppressed": self.is_suppressed(),
            "suppression_reasons": self.suppression_reasons,
        }

    def attach_suggestion(self) -> None:
        """Attach an actionable suggestion based on the issue kind."""
        if not self.suggestion:
            self.suggestion = SUGGESTION_MAP.get(self.kind, "")


@dataclass
class AnalysisContext:
    """Mutable context passed between analysis phases.

    Attributes:
        file_path: Source file path.
        source: Raw source text.
        code: Compiled code object.
        types: Type-inference results.
        patterns: Pattern-recognition results.
        ranges: Range-analysis results.
        taint: Variable-level taint sets.
        flow_analyzer: Flow-sensitive analyser instance.
        function_summaries: Inter-procedural function summaries.
        exception_handlers: Detected exception handler regions.
        none_check_analyzer: None-check analyser instance.
    """

    file_path: str
    source: str
    code: types.CodeType
    types: dict[str, object] = field(default_factory=dict[str, object])
    patterns: object = None
    ranges: dict[str, object] = field(default_factory=dict[str, object])
    taint: dict[str, set[TaintKind]] = field(default_factory=dict[str, set[TaintKind]])
    flow_analyzer: object | None = None
    function_summaries: dict[str, object] = field(default_factory=dict[str, object])
    exception_handlers: list[ExceptionHandlerInfo] = field(default_factory=list)
    none_check_analyzer: NoneCheckAnalyzerLike | None = None


class AnalysisPhase:
    """Abstract base class for scanner pipeline phases.

    Subclasses implement ``analyze()`` to inspect an ``AnalysisContext``
    and return any discovered ``ScanIssue`` instances.

    Attributes:
        name: Short identifier for the phase.
    """

    name: str = "base"

    def analyze(
        self,
        ctx: AnalysisContext,
        config: ScannerConfig,
    ) -> list[ScanIssue]:
        """Run analysis phase."""
        raise NotImplementedError
