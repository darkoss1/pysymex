# pysymex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
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

"""
Z3 Engine — Data types and enumerations.

Defines all enums, dataclasses, Z3 availability check, and value types
used throughout the Z3 verification engine.
"""

from __future__ import annotations

__version__ = "2.0.0"
__author__ = "pysymex Team"

import dis
import logging
from dataclasses import dataclass, field
from enum import Enum, auto

from pysymex._deps import ensure_z3_ready

_z3_import_error: RuntimeError | None = None

z3 = None
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


def _empty_instructions() -> list[dis.Instruction]:
    """Create a typed empty instruction list."""
    return []


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
    OVERFLOW = "integer_overflow"


class Severity(Enum):
    """Bug severity levels."""

    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5


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
class SymValue:
    """Enhanced symbolic value with type and origin metadata.

    Attributes:
        expr: Underlying Z3 expression.
        name: Human-readable name.
        sym_type: Symbolic type classification.
        is_none: Whether this value represents ``None``.
        is_list: Whether this value represents a list.
        length: Optional length expression for containers.
        origin: Description of where this value originated.
        constraints: Additional Z3 constraints specific to this value.
    """

    expr: object
    name: str = ""
    sym_type: SymType = SymType.UNKNOWN
    is_none: bool = False
    is_list: bool = False
    length: object | None = None
    origin: str = ""
    constraints: list[object] = field(default_factory=list[object])


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
    instructions: list[dis.Instruction] = field(default_factory=_empty_instructions)
    successors: list[tuple[int, str]] = field(default_factory=list[tuple[int, str]])
    predecessors: list[int] = field(default_factory=list[int])
    dominators: set[int] = field(default_factory=set[int])
    loop_header: bool = False
    reachable: bool = True
