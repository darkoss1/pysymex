"""Specialized bug detectors for pysymex.

This module provides sophisticated detectors for complex vulnerability patterns
including null dereference, security issues, resource leaks, integer overflow,
and unreachable code.
"""

from __future__ import annotations

import dis
from collections.abc import Callable
from typing import TYPE_CHECKING

import z3

from pysymex.analysis.detectors.base import Detector, DetectorRegistry, Issue, IssueKind
from pysymex.core.havoc import is_havoc

if TYPE_CHECKING:
    from pysymex.core.state import VMState

_IsSatFn = Callable[[list[z3.BoolRef]], bool]


def _pure_check_null_deref(
    top: object,
    opname: str,
    path_constraints: list[z3.BoolRef],
    pc: int,
    is_satisfiable_fn: _IsSatFn,
) -> Issue | None:
    """Pure: check whether *top* could be None for the given *opname*."""
    from pysymex.core.types import SymbolicNone, SymbolicValue

    if is_havoc(top):
        return None
    if isinstance(top, SymbolicNone):
        return Issue(
            kind=IssueKind.NULL_DEREFERENCE,
            message=f"Definite None dereference at {opname}",
            pc=pc,
        )
    if isinstance(top, SymbolicValue):
        none_check = [*path_constraints, top.is_none]
        if is_satisfiable_fn(none_check):
            # Suppress unconstrained vars that just happen to satisfy None
            must_be_none = not is_satisfiable_fn([*path_constraints, z3.Not(top.is_none)])
            is_unconstrained = z3.is_const(top.is_none) and top.is_none.decl().kind() == z3.Z3_OP_UNINTERPRETED
            if must_be_none or not is_unconstrained:
                from pysymex.core.solver import get_model

                return Issue(
                    kind=IssueKind.NULL_DEREFERENCE,
                    message=f"Possible None dereference at {opname}",
                    constraints=none_check,
                    model=get_model(none_check),
                    pc=pc,
                )
    return None


def _pure_check_bounded_overflow(
    left: object,
    right: object,
    argrepr: str,
    path_constraints: list[z3.BoolRef],
    pc: int,
    bits: int,
    min_val: int,
    max_val: int,
    is_satisfiable_fn: _IsSatFn,
) -> Issue | None:
    """Pure: check whether arithmetic on *left*/*right* can overflow within *bits*."""
    from pysymex.core.types import SymbolicValue

    if is_havoc(left) or is_havoc(right):
        return None
    if not (isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue)):
        return None
    if argrepr == "+":
        result_expr = left.z3_int + right.z3_int
    elif argrepr == "*":
        result_expr = left.z3_int * right.z3_int
    else:
        result_expr = left.z3_int - right.z3_int
    overflow_check = [
        *path_constraints,
        left.is_int,
        right.is_int,
        z3.Or(result_expr > max_val, result_expr < min_val),
    ]
    if is_satisfiable_fn(overflow_check):
        from pysymex.core.solver import get_model

        return Issue(
            kind=IssueKind.OVERFLOW,
            message=f"Potential {bits}-bit integer overflow",
            constraints=overflow_check,
            model=get_model(overflow_check),
            pc=pc,
        )
    return None


def _pure_check_unreachable(
    path_constraints: list[z3.BoolRef],
    pc: int,
    is_satisfiable_fn: _IsSatFn,
) -> Issue | None:
    """Pure: check whether *path_constraints* are unsatisfiable."""
    if path_constraints and not is_satisfiable_fn(path_constraints):
        return Issue(
            kind=IssueKind.UNREACHABLE_CODE,
            message="Unreachable code detected",
            pc=pc,
        )
    return None


class NullDereferenceDetector(Detector):
    """Detects potential null/None dereference on attribute access and subscript.

    Checks ``LOAD_ATTR``, ``LOAD_METHOD``, and ``BINARY_SUBSCR`` opcodes
    to determine if the top-of-stack value could be ``None``.
    """

    name = "null-dereference"
    description = "Detects potential None dereference"
    issue_kind = IssueKind.NULL_DEREFERENCE
    relevant_opcodes = frozenset({"LOAD_ATTR", "LOAD_METHOD", "BINARY_SUBSCR"})

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        is_satisfiable_fn: _IsSatFn,
    ) -> Issue | None:
        """Check for None dereference at attribute access or method calls."""
        if instruction.opname not in ("LOAD_ATTR", "LOAD_METHOD", "BINARY_SUBSCR"):
            return None
        if not state.stack:
            return None
        return _pure_check_null_deref(
            state.peek(),
            instruction.opname,
            list(state.path_constraints),
            state.pc,
            is_satisfiable_fn,
        )


class InfiniteLoopDetector(Detector):
    """Detects potential infinite loops via iteration counting and condition analysis.

    Attributes:
        _loop_counters: Per-PC iteration count.
        _max_iterations: Threshold that triggers an infinite-loop report.
    """

    name = "infinite-loop"
    description = "Detects potential infinite loops"
    issue_kind = IssueKind.INFINITE_LOOP
    relevant_opcodes = frozenset(
        {"JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT", "POP_JUMP_IF_FALSE", "POP_JUMP_IF_TRUE"}
    )

    def __init__(self):
        """Init."""
        """Initialize the class instance."""
        self._loop_counters: dict[int, int] = {}
        self._max_iterations = 1000

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        is_satisfiable_fn: _IsSatFn,
    ) -> Issue | None:
        """Check for infinite loop patterns."""
        if instruction.opname in ("JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT"):
            pc = state.pc
            self._loop_counters[pc] = self._loop_counters.get(pc, 0) + 1
            if self._loop_counters[pc] > self._max_iterations:
                return Issue(
                    kind=IssueKind.INFINITE_LOOP,
                    message=f"Potential infinite loop detected (>{self._max_iterations} iterations)",
                    pc=state.pc,
                )
        if instruction.opname in ("POP_JUMP_IF_FALSE", "POP_JUMP_IF_TRUE"):
            if state.stack:
                from pysymex.core.types import SymbolicValue

                cond = state.peek()
                if isinstance(cond, SymbolicValue):
                    always_true = [
                        *state.path_constraints,
                        cond.could_be_truthy(),
                    ]
                    can_be_false = [
                        *state.path_constraints,
                        z3.Not(cond.could_be_truthy()),
                    ]

                    if is_satisfiable_fn(always_true) and not is_satisfiable_fn(can_be_false):
                        target_pc = instruction.argval if instruction.argval is not None else 0
                        is_backward = target_pc < state.pc

                        if is_backward:
                            return Issue(
                                kind=IssueKind.INFINITE_LOOP,
                                message="Potential infinite loop detected (condition always true)",
                                pc=state.pc,
                            )
                        else:
                            return None
        return None


def _resolve_target_name(state: VMState, argc: int) -> str | None:
    """Resolve target name."""
    candidate_indices = [len(state.stack) - argc - 1, len(state.stack) - argc - 2]
    for index in candidate_indices:
        if index < 0 or index >= len(state.stack):
            continue
        candidate = state.stack[index]
        for attr in ("qualname", "name", "origin"):
            value = getattr(candidate, attr, None)
            if isinstance(value, str) and value:
                return value
    return None


class ResourceLeakDetector(Detector):
    """Detects potential resource leaks (unclosed files, connections, etc.)."""

    name = "resource-leak"
    description = "Detects potential resource leaks"
    issue_kind = IssueKind.RESOURCE_LEAK
    relevant_opcodes = frozenset({"CALL", "CALL_FUNCTION", "RETURN_VALUE", "RETURN_CONST"})

    def __init__(self):
        """Init."""
        """Initialize the class instance."""
        self._open_resources: int = 0

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        is_satisfiable_fn: _IsSatFn,
    ) -> Issue | None:
        """Check for resource leaks."""
        if instruction.opname in ("CALL", "CALL_FUNCTION"):
            argc = instruction.argval if instruction.argval is not None else instruction.arg
            target = _resolve_target_name(state, argc)
            if target == "open":
                self._open_resources += 1
            elif target and target.endswith(".close"):
                if self._open_resources > 0:
                    self._open_resources -= 1
        elif instruction.opname in ("RETURN_VALUE", "RETURN_CONST"):
            if self._open_resources > 0:
                count = self._open_resources
                self._open_resources = 0
                return Issue(
                    kind=IssueKind.RESOURCE_LEAK,
                    message=f"Potential resource leak: {count} unclosed resources",
                    pc=state.pc,
                )
        return None


class UseAfterFreeDetector(Detector):
    """Detects use-after-free patterns (e.g. using a closed file handle).

    Attributes:
        _freed_resources: Object IDs marked as freed/closed.
    """

    name = "use-after-free"
    description = "Detects use of released resources"
    issue_kind = IssueKind.ATTRIBUTE_ERROR
    relevant_opcodes = frozenset({"CALL", "CALL_FUNCTION", "LOAD_METHOD", "LOAD_ATTR"})

    def __init__(self):
        """Init."""
        """Initialize the class instance."""
        self._freed_vars: set[str] = set()

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        is_satisfiable_fn: _IsSatFn,
    ) -> Issue | None:
        """Check for use of freed/closed resources."""
        if instruction.opname in ("CALL", "CALL_FUNCTION"):
            argc = instruction.argval if instruction.argval is not None else instruction.arg
            target = _resolve_target_name(state, argc)
            if target and target.endswith(".close"):
                # Mark receiver as closed if possible
                if len(state.stack) >= argc + 2:
                    receiver = state.stack[-(argc + 2)]
                    if hasattr(receiver, "name"):
                        self._freed_vars.add(receiver.name)
        elif instruction.opname in ("LOAD_METHOD", "LOAD_ATTR"):
            if state.stack:
                top = state.peek()
                if hasattr(top, "name") and top.name in self._freed_vars:
                    return Issue(
                        kind=IssueKind.ATTRIBUTE_ERROR,
                        message=f"Use of closed/freed resource: {top.name}",
                        pc=state.pc,
                    )
        return None


class IntegerOverflowDetector(Detector):
    """Detects potential integer overflow issues.
    While Python integers don't overflow, this is useful for:
    - Bounded integer analysis
    - Interfacing with C extensions
    - Array index bounds
    """

    name = "bounded-overflow"
    description = "Detects potential bounded integer overflow"
    issue_kind = IssueKind.OVERFLOW
    relevant_opcodes = frozenset({"BINARY_OP"})
    INT32_MIN = -(2**31)
    INT32_MAX = 2**31 - 1
    INT64_MIN = -(2**63)
    INT64_MAX = 2**63 - 1

    def __init__(self, bits: int = 64):
        """Init."""
        """Initialize the class instance."""
        self.bits = bits
        self.min_val = -(2 ** (bits - 1))
        self.max_val = 2 ** (bits - 1) - 1

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        is_satisfiable_fn: _IsSatFn,
    ) -> Issue | None:
        """Check for integer overflow using BINARY_OP (Python 3.12+)."""
        if instruction.opname != "BINARY_OP":
            return None
        if instruction.argrepr not in ("+", "*", "-"):
            return None
        if len(state.stack) < 2:
            return None
        return _pure_check_bounded_overflow(
            state.peek(1),
            state.peek(),
            instruction.argrepr,
            list(state.path_constraints),
            state.pc,
            self.bits,
            self.min_val,
            self.max_val,
            is_satisfiable_fn,
        )


def _check_taint_in_args(state: VMState, argc: int) -> list[str]:
    """Check taint in args."""
    tainted_args: list[str] = []
    for i in range(1, argc + 1):
        if len(state.stack) >= i:
            val = state.stack[-i]
            labels = getattr(val, "taint_labels", set())
            if labels:
                tainted_args.extend(list(labels))
    return tainted_args


class FormatStringDetector(Detector):
    """Detects format string vulnerabilities."""

    name = "format-string"
    description = "Detects format string vulnerabilities"
    issue_kind = IssueKind.INVALID_ARGUMENT
    relevant_opcodes = frozenset({"FORMAT_VALUE", "FORMAT_SIMPLE", "BUILD_STRING"})

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        is_satisfiable_fn: _IsSatFn,
    ) -> Issue | None:
        """Check for format string issues."""
        if instruction.opname in ("FORMAT_VALUE", "FORMAT_SIMPLE"):
            if state.stack:
                val = state.peek()
                labels = getattr(val, "taint_labels", set())
                if labels:
                    return Issue(
                        kind=IssueKind.INVALID_ARGUMENT,
                        message=f"Format string vulnerability: Using tainted data ({', '.join(labels)}) in formatting",
                        pc=state.pc,
                    )
        elif instruction.opname == "BUILD_STRING":
            argc = instruction.argval if instruction.argval is not None else instruction.arg
            tainted = _check_taint_in_args(state, argc)
            if tainted:
                return Issue(
                    kind=IssueKind.INVALID_ARGUMENT,
                    message=f"Format string vulnerability: Using tainted data ({', '.join(tainted)}) in formatting",
                    pc=state.pc,
                )
        return None


class CommandInjectionDetector(Detector):
    """Detects potential command injection vulnerabilities."""

    name = "command-injection"
    description = "Detects potential command injection"
    issue_kind = IssueKind.INVALID_ARGUMENT
    relevant_opcodes = frozenset({"CALL", "CALL_FUNCTION"})
    DANGEROUS_FUNCTIONS = {
        "os.system",
        "os.popen",
        "subprocess.call",
        "subprocess.run",
        "subprocess.Popen",
        "eval",
        "exec",
    }

    def _is_dangerous_target(self, target_name: str | None) -> bool:
        """Is dangerous target."""
        if not target_name:
            return False
        normalized = target_name.lower()
        for dangerous in self.DANGEROUS_FUNCTIONS:
            dangerous_name = dangerous.lower()
            if normalized == dangerous_name:
                return True
            if "." in dangerous_name and normalized.endswith(f".{dangerous_name}"):
                return True
            if "." not in dangerous_name and normalized.endswith(f".{dangerous_name}"):
                return True
        return False

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        is_satisfiable_fn: _IsSatFn,
    ) -> Issue | None:
        """Check for command injection patterns (Tainted inputs flowing into CALLs)."""
        argc = instruction.argval if instruction.argval is not None else instruction.arg
        if argc is None or not isinstance(argc, int):
            return None
        target_name = _resolve_target_name(state, argc)
        if not self._is_dangerous_target(target_name):
            return None

        tainted_args = _check_taint_in_args(state, argc)
        if not tainted_args:
            return None

        return Issue(
            kind=IssueKind.INVALID_ARGUMENT,
            message=f"Command Injection / Tainted Call! Input derived from: {', '.join(tainted_args)} flows into {target_name}",
            pc=state.pc,
        )


class PathTraversalDetector(Detector):
    """Detects potential path traversal vulnerabilities."""

    name = "path-traversal"
    description = "Detects potential path traversal"
    issue_kind = IssueKind.INVALID_ARGUMENT
    relevant_opcodes = frozenset({"CALL", "CALL_FUNCTION"})
    PATH_FUNCTIONS = {
        "open",
        "os.open",
        "os.remove",
        "os.rmdir",
        "shutil.rmtree",
        "Path.open",
        "Path.unlink",
    }

    def _is_path_function(self, target_name: str | None) -> bool:
        """Is path function."""
        if not target_name:
            return False
        normalized = target_name.lower()
        for func in self.PATH_FUNCTIONS:
            if normalized == func.lower() or normalized.endswith(f".{func.lower()}"):
                return True
        return False

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        is_satisfiable_fn: _IsSatFn,
    ) -> Issue | None:
        """Check for path traversal patterns."""
        argc = instruction.argval if instruction.argval is not None else instruction.arg
        if argc is None or not isinstance(argc, int):
            return None
        target_name = _resolve_target_name(state, argc)
        if not self._is_path_function(target_name):
            return None

        tainted_args = _check_taint_in_args(state, argc)
        if not tainted_args:
            return None

        return Issue(
            kind=IssueKind.INVALID_ARGUMENT,
            message=f"Path Traversal Pattern: Tainted data ({', '.join(tainted_args)}) flows into file operation {target_name}",
            pc=state.pc,
        )


class SQLInjectionDetector(Detector):
    """Detects potential SQL injection vulnerabilities."""

    name = "sql-injection"
    description = "Detects potential SQL injection"
    issue_kind = IssueKind.INVALID_ARGUMENT
    relevant_opcodes = frozenset({"CALL", "CALL_FUNCTION"})
    SQL_METHODS = {"execute", "executemany", "executescript"}

    def _is_sql_function(self, target_name: str | None) -> bool:
        """Is sql function."""
        if not target_name:
            return False
        normalized = target_name.lower()
        for func in self.SQL_METHODS:
            if normalized == func or normalized.endswith(f".{func}"):
                return True
        return False

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        is_satisfiable_fn: _IsSatFn,
    ) -> Issue | None:
        """Check for SQL injection patterns."""
        argc = instruction.argval if instruction.argval is not None else instruction.arg
        if argc is None or not isinstance(argc, int):
            return None
        target_name = _resolve_target_name(state, argc)
        if not self._is_sql_function(target_name):
            return None

        # Check if the query argument (usually args[0]) is tainted
        if len(state.stack) >= argc:
            query_arg = state.stack[-argc]
            labels = getattr(query_arg, "taint_labels", set())
            if labels:
                return Issue(
                    kind=IssueKind.INVALID_ARGUMENT,
                    message=f"SQL Injection Pattern: Tainted query ({', '.join(labels)}) executed by {target_name}",
                    pc=state.pc,
                )
        return None


class UnreachableCodeDetector(Detector):
    """Detects unreachable code paths."""

    name = "unreachable-code"
    description = "Detects unreachable code"
    issue_kind = IssueKind.UNREACHABLE_CODE
    relevant_opcodes = frozenset()

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        is_satisfiable_fn: _IsSatFn,
    ) -> Issue | None:
        """Check if current code is unreachable."""
        return _pure_check_unreachable(
            list(state.path_constraints),
            state.pc,
            is_satisfiable_fn,
        )


def register_advanced_detectors(registry: DetectorRegistry) -> None:
    """Register all advanced detectors with a registry.

    Args:
        registry: The ``DetectorRegistry`` to populate.
    """
    registry.register(NullDereferenceDetector)
    registry.register(InfiniteLoopDetector)
    registry.register(IntegerOverflowDetector)
    registry.register(UnreachableCodeDetector)
    registry.register(UseAfterFreeDetector)
    registry.register(CommandInjectionDetector)
    registry.register(ResourceLeakDetector)
    registry.register(FormatStringDetector)
    registry.register(PathTraversalDetector)
    registry.register(SQLInjectionDetector)


__all__ = [
    "CommandInjectionDetector",
    "FormatStringDetector",
    "InfiniteLoopDetector",
    "IntegerOverflowDetector",
    "NullDereferenceDetector",
    "PathTraversalDetector",
    "ResourceLeakDetector",
    "SQLInjectionDetector",
    "UnreachableCodeDetector",
    "UseAfterFreeDetector",
    "register_advanced_detectors",
]
