"""Enhanced detector types, enums, and base class.

Provides:
- IssueKind: Enum of detectable issue categories
- Severity: Enum of severity levels
- Issue: Dataclass representing a detected issue
- DetectionContext: Context provided to detectors during analysis
- StaticDetector: Abstract base class for all enhanced detectors
"""

from __future__ import annotations


import dis

from abc import ABC, abstractmethod

from collections.abc import Sequence

from dataclasses import dataclass

from enum import Enum, auto

from typing import Any


from pysymex.analysis.flow_sensitive import FlowContext

from pysymex.analysis.patterns import (
    FunctionPatternInfo,
    PatternKind,
)

from pysymex.analysis.type_inference import (
    PyType,
    TypeEnvironment,
    TypeKind,
)


class IssueKind(Enum):
    """Categories of issues that can be detected."""

    TYPE_ERROR = auto()

    ATTRIBUTE_ERROR = auto()

    INDEX_ERROR = auto()

    KEY_ERROR = auto()

    DIVISION_BY_ZERO = auto()

    OVERFLOW_ERROR = auto()

    MODULO_BY_ZERO = auto()

    VALUE_ERROR = auto()

    ASSERTION_ERROR = auto()

    UNBOUND_LOCAL = auto()

    NAME_ERROR = auto()

    NONE_DEREFERENCE = auto()

    RESOURCE_LEAK = auto()

    DEAD_CODE = auto()

    UNREACHABLE_CODE = auto()

    INFINITE_LOOP = auto()

    TAINT_ERROR = auto()

    INJECTION = auto()


class Severity(Enum):
    """Severity levels for issues."""

    CRITICAL = auto()

    HIGH = auto()

    MEDIUM = auto()

    LOW = auto()

    ERROR = auto()

    WARNING = auto()

    INFO = auto()

    HINT = auto()


@dataclass
class Issue:
    """Represents a detected issue."""

    kind: IssueKind

    severity: Severity

    file: str

    line: int

    message: str

    column: int | None = None

    pc: int | None = None

    explanation: str | None = None

    confidence: float = 1.0

    related_code: str | None = None

    fix_suggestion: str | None = None

    detector_name: str | None = None

    suppression_reason: str | None = None

    def is_suppressed(self) -> bool:
        """Check if issue was suppressed."""

        return self.suppression_reason is not None

    def format(self) -> str:
        """Format the issue for display."""

        sev = self.severity.name.lower()

        kind = self.kind.name.replace("_", " ").lower()

        loc = f"{self.file}:{self.line}"

        if self.column:
            loc += f":{self.column}"

        conf = f" ({self.confidence:.0%} confident)" if self.confidence < 1.0 else ""

        return f"[{sev}] {kind} at {loc}{conf}: {self.message}"


@dataclass
class DetectionContext:
    """
    Context provided to detectors during analysis.
    Contains all available analysis information.
    """

    code: Any

    instructions: Sequence[dis.Instruction]

    pc: int

    instruction: dis.Instruction

    line: int

    type_env: TypeEnvironment

    flow_context: FlowContext | None = None

    pattern_info: FunctionPatternInfo | None = None

    file_path: str = ""

    function_name: str = ""

    symbolic_state: Any | None = None

    patterns: Any | None = None

    cfg: Any | None = None

    imports: Any | None = None

    global_types: Any | None = None

    def get_type(self, var_name: str) -> PyType:
        """Get type of a variable."""

        return self.type_env.get_type(var_name)

    def is_definitely_type(self, var_name: str, kind: TypeKind) -> bool:
        """Check if variable is definitely of a type."""

        var_type = self.type_env.get_type(var_name)

        return var_type.kind == kind

    def can_pattern_suppress(self, error_type: str) -> bool:
        """Check if a pattern suppresses an error at this PC."""

        if self.pattern_info is None:
            return False

        return not self.pattern_info.can_error_occur(self.pc, error_type)

    def is_in_try_block(self, exception_type: str) -> bool:
        """Check if current PC is in a try block catching the exception."""

        if self.pattern_info is None:
            return False

        patterns = self.pattern_info.matcher.get_patterns_at(self.pc)

        for pattern in patterns:
            if pattern.kind == PatternKind.TRY_EXCEPT_PATTERN:
                caught = pattern.variables.get("caught_exceptions", set())

                if exception_type in caught or "Exception" in caught:
                    return True

        return False


class StaticDetector(ABC):
    """
    Base class for enhanced detectors.
    Provides framework for detectors that integrate with:
    - Type inference
    - Flow analysis
    - Pattern recognition
    """

    def __init__(self) -> None:
        self.name = self.__class__.__name__

        self.issues: list[Issue] = []

    @abstractmethod
    def issue_kind(self) -> IssueKind:
        """Return the kind of issues this detector finds."""

    @abstractmethod
    def check(self, ctx: DetectionContext) -> Issue | None:
        """
        Check for issues at the current context.
        Returns an Issue if one is found, None otherwise.
        The issue may have a suppression_reason if it was suppressed.
        """

    def should_check(self, ctx: DetectionContext) -> bool:
        """
        Determine if this detector should run at this context.
        Override for efficiency to skip irrelevant instructions.
        """

        return True

    def get_severity(self, confidence: float) -> Severity:
        """Determine severity based on confidence."""

        if confidence >= 0.95:
            return Severity.ERROR

        elif confidence >= 0.75:
            return Severity.WARNING

        elif confidence >= 0.5:
            return Severity.INFO

        else:
            return Severity.HINT

    def create_issue(
        self,
        ctx: DetectionContext,
        message: str,
        confidence: float = 1.0,
        explanation: str | None = None,
        fix_suggestion: str | None = None,
    ) -> Issue:
        """Create an issue with context information."""

        return Issue(
            kind=self.issue_kind(),
            severity=self.get_severity(confidence),
            file=ctx.file_path,
            line=ctx.line,
            pc=ctx.pc,
            message=message,
            explanation=explanation,
            confidence=confidence,
            fix_suggestion=fix_suggestion,
            detector_name=self.name,
        )

    def suppress_issue(
        self,
        issue: Issue,
        reason: str,
    ) -> Issue:
        """Mark an issue as suppressed."""

        issue.suppression_reason = reason

        return issue
