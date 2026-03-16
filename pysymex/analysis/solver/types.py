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

_z3_import_error: RuntimeError | None = None

z3: Any
_z3_available = False
try:
    z3 = ensure_z3_ready()
    _z3_available = True
except RuntimeError as exc:
    _z3_available = False
    z3 = None
    _z3_import_error = exc

Z3_AVAILABLE: bool = _z3_available
Z3_IMPORT_ERROR: RuntimeError | None = _z3_import_error

logger = logging.getLogger(__name__)


class BugType(Enum):
    """Types of bugs the Z3 engine can prove or disprove.

    Each member corresponds to a distinct class of runtime error.
    """

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


@dataclass(frozen=True, slots=True)
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


@dataclass(frozen=True, slots=True)
class SymValue:
    """Enhanced symbolic value with type, taint, and origin metadata.

    Attributes:
        expr: Underlying Z3 expression.
        name: Human-readable name.
        sym_type: Symbolic type classification.
        is_none: Whether this value represents ``None``.
        is_list: Whether this value represents a list.
        length: Optional length expression for containers.
        taint: Taint provenance information.
        origin: Description of where this value originated.
        constraints: Additional Z3 constraints specific to this value.
    """

    expr: object
    name: str = ""
    sym_type: SymType = SymType.UNKNOWN
    is_none: bool = False
    is_list: bool = False
    length: object | None = None
    taint: TaintInfo = field(default_factory=TaintInfo)
    origin: str = ""
    constraints: list[object] = field(default_factory=list[object])

    @property
    def is_tainted(self) -> bool:
        """Property returning the is_tainted."""
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


@dataclass(frozen=True, slots=True)
class CrashCondition:
    """A condition under which a crash occurs.

    Attributes:
        bug_type: The category of bug.
        condition: Z3 expression that, when satisfiable, triggers the crash.
        path_constraints: Collected path constraints at the crash site.
        line: Source line number.
        function: Enclosing function name.
        description: Human-readable crash description.
        variables: Map of relevant variable names to Z3 expressions.
        severity: Bug severity level.
        call_stack: Call-stack frames at detection time.
        taint_info: Optional taint provenance.
        file_path: Source file path.
    """

    bug_type: BugType
    condition: object
    path_constraints: list[object]
    line: int
    function: str
    description: str
    variables: dict[str, object] = field(default_factory=dict[str, object])
    severity: Severity = Severity.HIGH
    call_stack: list[str] = field(default_factory=list[str])
    taint_info: TaintInfo | None = None
    file_path: str = ""


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Result of formal verification."""

    crash: CrashCondition
    can_crash: bool
    proven_safe: bool
    counterexample: dict[str, str] | None = None
    z3_status: str = ""
    verification_time_ms: float = 0.0
    path_explored: int = 0


@dataclass(frozen=True, slots=True)
class FunctionSummary:
    """Summary of a function's behaviour for inter-procedural analysis.

    Allows efficient re-use without re-analysing the function body.

    Attributes:
        name: Function name.
        code_hash: SHA-256 prefix of the bytecode.
        parameters: Parameter names.
        return_constraints: Constraints on the return value.
        crash_conditions: Detected crash conditions.
        modifies_globals: Global variable names the function may write.
        calls_functions: Names of called functions.
        may_return_none: Whether the function can return ``None``.
        may_raise: Whether the function can raise an exception.
        taint_propagation: Mapping of param→taint-output paths.
        pure: True if the function has no side effects.
        analyzed_at: Timestamp of analysis.
        verified: Whether verification completed.
        has_bugs: Whether any bugs were found.
    """

    name: str
    code_hash: str
    parameters: list[str]
    return_constraints: list[object]
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


@dataclass(frozen=True, slots=True)
class CallSite:
    """Information about a function call site in the Z3 engine's CFG.

    Attributes:
        caller: Name of the calling function.
        callee: Name of the called function.
        line: Source line of the call.
        arguments: Argument names passed to the callee.
        file_path: Source file containing the call.
    """

    caller: str
    callee: str
    line: int
    arguments: list[str]
    file_path: str = ""


@dataclass
class BasicBlock:
    """Basic block in the control-flow graph.

    Attributes:
        id: Unique block identifier.
        instructions: Bytecode instructions in this block.
        successors: List of ``(block_id, edge_type)`` pairs.
        predecessors: IDs of predecessor blocks.
        dominators: Set of dominator block IDs.
        loop_header: Whether this block heads a loop.
        reachable: Whether the block is reachable from entry.
    """

    id: int
    instructions: list[object] = field(default_factory=list)
    successors: list[tuple[int, str]] = field(default_factory=list[tuple[int, str]])
    predecessors: list[int] = field(default_factory=list[int])
    dominators: set[int] = field(default_factory=set[int])
    loop_header: bool = False
    reachable: bool = True
