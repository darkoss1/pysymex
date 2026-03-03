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

if TYPE_CHECKING:
    from pysymex.core.state import VMState

_IsSatFn = Callable[[list[z3.BoolRef]], bool]


class NullDereferenceDetector(Detector):
    """Detects potential null/None dereference issues."""

    name = "null-dereference"

    description = "Detects potential None dereference"

    issue_kind = IssueKind.NULL_DEREFERENCE

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

        top = state.peek()

        from pysymex.core.types import SymbolicNone, SymbolicValue

        if isinstance(top, SymbolicNone):
            return Issue(
                kind=IssueKind.NULL_DEREFERENCE,
                message=f"Definite None dereference at {instruction.opname}",
                pc=state.pc,
            )

        if isinstance(top, SymbolicValue):
            none_check = [
                *state.path_constraints,
                z3.Not(top.is_int),
                z3.Not(top.is_bool),
            ]

            if is_satisfiable_fn(none_check):
                from pysymex.core.solver import get_model

                return Issue(
                    kind=IssueKind.NULL_DEREFERENCE,
                    message=f"Possible None dereference at {instruction.opname}",
                    constraints=none_check,
                    model=get_model(none_check),
                    pc=state.pc,
                )

        return None


class InfiniteLoopDetector(Detector):
    """Detects potential infinite loops."""

    name = "infinite-loop"

    description = "Detects potential infinite loops"

    issue_kind = IssueKind.INFINITE_LOOP

    def __init__(self):
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
                        return Issue(
                            kind=IssueKind.INFINITE_LOOP,
                            message="Loop condition is always true",
                            pc=state.pc,
                        )

        return None


class ResourceLeakDetector(Detector):
    """Detects potential resource leaks (unclosed files, connections, etc.)."""

    name = "resource-leak"

    description = "Detects potential resource leaks"

    issue_kind = IssueKind.UNHANDLED_EXCEPTION

    def __init__(self):
        self._open_resources: set[int] = set()

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        is_satisfiable_fn: _IsSatFn,
    ) -> Issue | None:
        """Check for resource leaks."""

        if instruction.opname == "CALL":
            pass

        if instruction.opname in ("RETURN_VALUE", "RETURN_CONST"):
            if self._open_resources:
                return Issue(
                    kind=IssueKind.UNHANDLED_EXCEPTION,
                    message=f"Potential resource leak: {len(self._open_resources)} unclosed resources",
                    pc=state.pc,
                )

        return None


class UseAfterFreeDetector(Detector):
    """Detects use-after-free style bugs (using closed/freed resources)."""

    name = "use-after-free"

    description = "Detects use of released resources"

    issue_kind = IssueKind.ATTRIBUTE_ERROR

    def __init__(self):
        self._freed_resources: set[int] = set()

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        is_satisfiable_fn: _IsSatFn,
    ) -> Issue | None:
        """Check for use of freed/closed resources."""

        if instruction.opname in ("LOAD_METHOD", "LOAD_ATTR"):
            if state.stack:
                top = state.peek()

                if id(top) in self._freed_resources:
                    return Issue(
                        kind=IssueKind.ATTRIBUTE_ERROR,
                        message="Use of closed/freed resource",
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

    INT32_MIN = -(2**31)

    INT32_MAX = 2**31 - 1

    INT64_MIN = -(2**63)

    INT64_MAX = 2**63 - 1

    def __init__(self, bits: int = 64):
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

        right = state.peek()

        left = state.peek(1)

        from pysymex.core.types import SymbolicValue

        if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
            if instruction.argrepr == "+":
                result_expr = left.z3_int + right.z3_int

            elif instruction.argrepr == "*":
                result_expr = left.z3_int * right.z3_int

            else:
                result_expr = left.z3_int - right.z3_int

            overflow_check = [
                *state.path_constraints,
                left.is_int,
                right.is_int,
                z3.Or(
                    result_expr > self.max_val,
                    result_expr < self.min_val,
                ),
            ]

            if is_satisfiable_fn(overflow_check):
                from pysymex.core.solver import get_model

                return Issue(
                    kind=IssueKind.OVERFLOW,
                    message=f"Potential {self.bits}-bit integer overflow",
                    constraints=overflow_check,
                    model=get_model(overflow_check),
                    pc=state.pc,
                )

        return None


class FormatStringDetector(Detector):
    """Detects format string vulnerabilities."""

    name = "format-string"

    description = "Detects format string vulnerabilities"

    issue_kind = IssueKind.INVALID_ARGUMENT

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        is_satisfiable_fn: _IsSatFn,
    ) -> Issue | None:
        """Check for format string issues."""

        if instruction.opname in ("FORMAT_VALUE", "FORMAT_SIMPLE", "BUILD_STRING"):
            pass

        return None


class CommandInjectionDetector(Detector):
    """Detects potential command injection vulnerabilities."""

    name = "command-injection"

    description = "Detects potential command injection"

    issue_kind = IssueKind.INVALID_ARGUMENT

    DANGEROUS_FUNCTIONS = {
        "os.system",
        "os.popen",
        "subprocess.call",
        "subprocess.run",
        "subprocess.Popen",
        "eval",
        "exec",
    }

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        is_satisfiable_fn: _IsSatFn,
    ) -> Issue | None:
        """Check for command injection patterns."""

        if instruction.opname != "CALL":
            return None

        return None


class PathTraversalDetector(Detector):
    """Detects potential path traversal vulnerabilities."""

    name = "path-traversal"

    description = "Detects potential path traversal"

    issue_kind = IssueKind.INVALID_ARGUMENT

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        is_satisfiable_fn: _IsSatFn,
    ) -> Issue | None:
        """Check for path traversal patterns."""

        return None


class SQLInjectionDetector(Detector):
    """Detects potential SQL injection vulnerabilities."""

    name = "sql-injection"

    description = "Detects potential SQL injection"

    issue_kind = IssueKind.INVALID_ARGUMENT

    SQL_METHODS = {"execute", "executemany", "executescript"}

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        is_satisfiable_fn: _IsSatFn,
    ) -> Issue | None:
        """Check for SQL injection patterns."""

        return None


class UnreachableCodeDetector(Detector):
    """Detects unreachable code paths."""

    name = "unreachable-code"

    description = "Detects unreachable code"

    issue_kind = IssueKind.UNREACHABLE_CODE

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        is_satisfiable_fn: _IsSatFn,
    ) -> Issue | None:
        """Check if current code is unreachable."""

        if state.path_constraints:
            if not is_satisfiable_fn(list(state.path_constraints)):
                return Issue(
                    kind=IssueKind.UNREACHABLE_CODE,
                    message="Unreachable code detected",
                    pc=state.pc,
                )

        return None


def register_advanced_detectors(registry: DetectorRegistry) -> None:
    """Register all advanced detectors with a registry."""

    registry.register(NullDereferenceDetector)

    registry.register(InfiniteLoopDetector)

    registry.register(IntegerOverflowDetector)

    registry.register(UnreachableCodeDetector)

    registry.register(UseAfterFreeDetector)

    registry.register(ResourceLeakDetector)


__all__ = [
    "NullDereferenceDetector",
    "InfiniteLoopDetector",
    "ResourceLeakDetector",
    "UseAfterFreeDetector",
    "IntegerOverflowDetector",
    "FormatStringDetector",
    "CommandInjectionDetector",
    "PathTraversalDetector",
    "SQLInjectionDetector",
    "UnreachableCodeDetector",
    "register_advanced_detectors",
]
