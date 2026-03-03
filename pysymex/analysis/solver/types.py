"""
Z3 Engine — Data types and enumerations.

Defines all enums, dataclasses, Z3 availability check, and value types
used throughout the Z3 verification engine.
"""

from __future__ import annotations

__version__ = "2.0.0"

__author__ = "PySyMex Team"


import logging

from dataclasses import dataclass, field

from enum import Enum, auto

from typing import Any


from pysymex._deps import ensure_z3_ready

Z3_IMPORT_ERROR: RuntimeError | None = None


z3: Any

Z3_AVAILABLE: bool

try:
    z3 = ensure_z3_ready()

    Z3_AVAILABLE = True

except RuntimeError as exc:
    Z3_AVAILABLE = False

    z3 = None

    Z3_IMPORT_ERROR = exc

logger = logging.getLogger(__name__)


class BugType(Enum):
    """Types of bugs we can prove/disprove."""

    DIVISION_BY_ZERO = "division_by_zero"

    MODULO_BY_ZERO = "modulo_by_zero"

    INDEX_OUT_OF_BOUNDS = "index_out_of_bounds"

    NEGATIVE_SHIFT = "negative_shift"

    NONE_DEREFERENCE = "none_dereference"

    TYPE_ERROR = "type_error"

    ASSERTION_FAILURE = "assertion_failure"

    KEY_ERROR = "key_error"

    ATTRIBUTE_ERROR = "attribute_error"

    UNREACHABLE_CODE = "unreachable_code"

    TAINTED_SINK = "tainted_data_to_sink"

    OVERFLOW = "integer_overflow"


class Severity(Enum):
    """Bug severity levels."""

    CRITICAL = 1

    HIGH = 2

    MEDIUM = 3

    LOW = 4

    INFO = 5


class TaintSource(Enum):
    """Sources of untrusted data."""

    USER_INPUT = "user_input"

    FILE_READ = "file_read"

    NETWORK = "network"

    ENVIRONMENT = "environment"

    DATABASE = "database"

    UNKNOWN = "unknown"


class SymType(Enum):
    """Type classification for symbolic values."""

    INT = auto()

    REAL = auto()

    BOOL = auto()

    NONE = auto()

    LIST = auto()

    DICT = auto()

    STRING = auto()

    TUPLE = auto()

    SET = auto()

    CALLABLE = auto()

    OBJECT = auto()

    UNKNOWN = auto()


@dataclass
class TaintInfo:
    """Tracks taint information for a value."""

    is_tainted: bool = False

    sources: set[TaintSource] = field(default_factory=set[TaintSource])

    propagation_path: list[str] = field(default_factory=list[str])

    @property
    def source(self) -> TaintSource | None:
        """Return the primary taint source (first in set), or None."""

        return next(iter(self.sources), None) if self.sources else None

    def propagate(self, operation: str) -> TaintInfo:
        """Create new taint info propagated through an operation."""

        if not self.is_tainted:
            return TaintInfo()

        return TaintInfo(
            is_tainted=True,
            sources=self.sources.copy(),
            propagation_path=self.propagation_path + [operation],
        )


@dataclass
class SymValue:
    """
    Enhanced symbolic value with rich metadata.
    """

    expr: Any

    name: str = ""

    sym_type: SymType = SymType.UNKNOWN

    is_none: bool = False

    is_list: bool = False

    length: Any | None = None

    taint: TaintInfo = field(default_factory=TaintInfo)

    origin: str = ""

    constraints: list[Any] = field(default_factory=list[Any])

    @property
    def is_tainted(self) -> bool:
        return self.taint.is_tainted

    def with_taint(self, source: TaintSource, path: str = "") -> SymValue:
        """Create a tainted copy of this value."""

        new_taint = TaintInfo(
            is_tainted=True, sources={source}, propagation_path=[path] if path else []
        )

        return SymValue(
            self.expr,
            self.name,
            self.sym_type,
            self.is_none,
            self.is_list,
            self.length,
            new_taint,
            self.origin,
            self.constraints.copy(),
        )


@dataclass
class CrashCondition:
    """A condition that causes a crash."""

    bug_type: BugType

    condition: Any

    path_constraints: list[Any]

    line: int

    function: str

    description: str

    variables: dict[str, Any] = field(default_factory=dict[str, Any])

    severity: Severity = Severity.HIGH

    call_stack: list[str] = field(default_factory=list[str])

    taint_info: TaintInfo | None = None

    file_path: str = ""


@dataclass
class VerificationResult:
    """Result of formal verification."""

    crash: CrashCondition

    can_crash: bool

    proven_safe: bool

    counterexample: dict[str, str] | None = None

    z3_status: str = ""

    verification_time_ms: float = 0.0

    path_explored: int = 0


@dataclass
class FunctionSummary:
    """
    Summary of a function's behavior for interprocedural analysis.
    Allows efficient re-use without re-analyzing.
    """

    name: str

    code_hash: str

    parameters: list[str]

    return_constraints: list[Any]

    crash_conditions: list[CrashCondition]

    modifies_globals: set[str]

    calls_functions: set[str]

    may_return_none: bool

    may_raise: bool

    taint_propagation: dict[str, set[str]]

    pure: bool

    analyzed_at: float = 0.0

    verified: bool = False

    has_bugs: bool = False


@dataclass
class CallSite:
    """Information about a function call site."""

    caller: str

    callee: str

    line: int

    arguments: list[str]

    file_path: str = ""


@dataclass
class BasicBlock:
    """Basic block in control flow graph."""

    id: int

    instructions: list[Any] = field(default_factory=list[Any])

    successors: list[tuple[int, str]] = field(default_factory=list[tuple[int, str]])

    predecessors: list[int] = field(default_factory=list[int])

    dominators: set[int] = field(default_factory=set[int])

    loop_header: bool = False

    reachable: bool = True
