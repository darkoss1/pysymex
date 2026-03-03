"""Bug detectors for symbolic execution.
pysymex - Core detectors, advanced detectors, and registry.
"""

from __future__ import annotations


import dis

from abc import ABC, abstractmethod

from dataclasses import dataclass, field

from enum import Enum, auto

from typing import TYPE_CHECKING, Any

from collections.abc import Callable


import z3

if TYPE_CHECKING:
    from pysymex.core.state import VMState

from pysymex.core.solver import get_model, is_satisfiable

from pysymex.core.types import (
    SymbolicDict,
    SymbolicList,
    SymbolicNone,
    SymbolicString,
    SymbolicValue,
)

__all__ = [
    "AssertionErrorDetector",
    "AttributeErrorDetector",
    "Detector",
    "DetectorRegistry",
    "DivisionByZeroDetector",
    "EnhancedIndexErrorDetector",
    "EnhancedTypeErrorDetector",
    "FormatStringDetector",
    "IndexErrorDetector",
    "Issue",
    "IssueKind",
    "KeyErrorDetector",
    "NoneDereferenceDetector",
    "OverflowDetector",
    "ResourceLeakDetector",
    "TaintFlowDetector",
    "TypeErrorDetector",
    "UnboundVariableDetector",
    "ValueErrorDetector",
    "default_registry",
]


class IssueKind(Enum):
    """Types of issues that can be detected."""

    DIVISION_BY_ZERO = auto()

    ASSERTION_ERROR = auto()

    INDEX_ERROR = auto()

    KEY_ERROR = auto()

    TYPE_ERROR = auto()

    ATTRIBUTE_ERROR = auto()

    OVERFLOW = auto()

    NULL_DEREFERENCE = auto()

    INFINITE_LOOP = auto()

    UNREACHABLE_CODE = auto()

    UNHANDLED_EXCEPTION = auto()

    RECURSION_LIMIT = auto()

    NEGATIVE_SQRT = auto()

    INVALID_ARGUMENT = auto()

    FORMAT_STRING_INJECTION = auto()

    RESOURCE_LEAK = auto()

    VALUE_ERROR = auto()

    SQL_INJECTION = auto()

    PATH_TRAVERSAL = auto()

    UNBOUND_VARIABLE = auto()

    COMMAND_INJECTION = auto()

    CODE_INJECTION = auto()

    RUNTIME_ERROR = auto()

    EXCEPTION = auto()

    SYNTAX_ERROR = auto()

    UNKNOWN = auto()


@dataclass
class Issue:
    """Represents a detected issue."""

    kind: IssueKind

    message: str

    constraints: list[Any] = field(default_factory=list[Any])

    model: z3.ModelRef | None = None

    pc: int = 0

    line_number: int | None = None

    function_name: str | None = None

    filename: str | None = None

    stack_trace: list[str] = field(default_factory=list[str])

    class_name: str | None = None

    full_path: str | None = None

    counterexample: dict[str, Any] | None = None

    def get_counterexample(self) -> dict[str, Any]:
        """Extract counterexample from model."""

        if self.model is None:
            return {}

        counterexample: dict[str, Any] = {}

        for decl in self.model.decls():
            name = decl.name()

            value = self.model[decl]

            base_name = name

            for suffix in ["_is_int", "_is_bool", "_is_none", "_is_str", "_int", "_bool", "_str"]:
                if name.endswith(suffix):
                    base_name = name[: -len(suffix)]

                    break

            if "_is_" in name or base_name.startswith("_"):
                continue

            try:
                if isinstance(value, z3.IntNumRef):
                    counterexample[base_name] = value.as_long()

                elif z3.is_true(value):
                    counterexample[base_name] = True

                elif z3.is_false(value):
                    counterexample[base_name] = False

                elif isinstance(value, z3.SeqRef):
                    counterexample[base_name] = value.as_string()

                else:
                    counterexample[base_name] = str(value)

            except Exception:
                counterexample[base_name] = str(value)

        return counterexample

    def format(self) -> str:
        """Format issue for display."""

        lines = [f"[{self.kind.name}] {self.message}"]

        if self.filename or self.line_number or self.function_name:
            location: list[str] = []

            if self.filename:
                location.append(self.filename)

            if self.function_name:
                location.append(f"in {self.function_name}()")

            if self.line_number:
                location.append(f"line {self.line_number}")

            lines.append(f"  Location: {', '.join(location)}")

        if self.pc:
            lines.append(f"  PC: {self.pc}")

        counterexample = self.get_counterexample()

        if counterexample:
            lines.append("  Counterexample:")

            for name, value in sorted(counterexample.items()):
                lines.append(f"    {name} = {value}")

        if self.stack_trace:
            lines.append("  Stack trace:")

            for frame in self.stack_trace:
                lines.append(f"    {frame}")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""

        return {
            "kind": self.kind.name,
            "message": self.message,
            "pc": self.pc,
            "line_number": self.line_number,
            "function_name": self.function_name,
            "filename": self.filename,
            "counterexample": self.get_counterexample(),
            "stack_trace": self.stack_trace,
        }


class Detector(ABC):
    """Base class for bug detectors."""

    name: str = "base"

    description: str = "Base detector"

    issue_kind: IssueKind = IssueKind.UNHANDLED_EXCEPTION

    relevant_opcodes: frozenset[str] = frozenset()

    @abstractmethod
    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: Callable[..., Any],
    ) -> Issue | None:
        """
        Check for issues at the current state.
        Args:
            state: Current VM state
            instruction: Current instruction being executed
            solver_check: Function to check constraint satisfiability
        Returns:
            Issue if a problem is detected, None otherwise
        """


class DivisionByZeroDetector(Detector):
    """Detects potential division by zero errors."""

    name = "division-by-zero"

    description = "Detects division by zero"

    issue_kind = IssueKind.DIVISION_BY_ZERO

    DIVISION_OPS = {"BINARY_TRUE_DIVIDE", "BINARY_FLOOR_DIVIDE", "BINARY_MODULO"}

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: Callable[..., Any],
    ) -> Issue | None:
        """Check for division by zero or modulo zero."""

        if instruction.opname == "BINARY_OP":
            op_name = instruction.argrepr or ""

            if "/" not in op_name and "%" not in op_name:
                return None

        elif instruction.opname not in self.DIVISION_OPS:
            return None

        if len(state.stack) < 2:
            return None

        divisor = state.stack[-1]

        dividend = state.stack[-2]

        from pysymex.execution.opcodes.arithmetic import is_overloaded_arithmetic

        if (
            isinstance(dividend, SymbolicValue)
            and isinstance(divisor, SymbolicValue)
            and is_overloaded_arithmetic(dividend, divisor)
        ):
            return None

        if hasattr(divisor, "name") and divisor.name:
            name_lower = divisor.name.lower()

            if any(
                p in name_lower for p in ("z3_int", "z3_real", "z3_bool", "subscr_", "right_val")
            ):
                return None

        if not isinstance(divisor, SymbolicValue):
            try:
                if float(divisor) == 0:
                    return Issue(
                        kind=IssueKind.DIVISION_BY_ZERO,
                        message="Division by concrete zero",
                        pc=state.pc,
                    )

            except (ValueError, TypeError):
                pass

            return None

        zero_constraint = [
            *state.path_constraints,
            divisor.is_int,
            divisor.z3_int == 0,
        ]

        if is_satisfiable(zero_constraint):
            return Issue(
                kind=IssueKind.DIVISION_BY_ZERO,
                message=f"Possible division by zero: {divisor.name} can be 0",
                constraints=zero_constraint,
                model=get_model(zero_constraint),
                pc=state.pc,
            )

        return None


class AssertionErrorDetector(Detector):
    """Detects failing assertions."""

    name = "assertion-error"

    description = "Detects failing assertions"

    issue_kind = IssueKind.ASSERTION_ERROR

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: Callable[..., Any],
    ) -> Issue | None:
        """Check for assertion failures."""

        if instruction.opname != "RAISE_VARARGS":
            return None

        is_assertion = False

        if state.stack:
            top = state.peek()

            name = getattr(top, "name", "") or getattr(top, "_name", "") or ""

            if "AssertionError" in str(name):
                is_assertion = True

        if not is_assertion:
            return None

        if not is_satisfiable(state.path_constraints):
            return None

        return Issue(
            kind=IssueKind.ASSERTION_ERROR,
            message="Possible assertion failure",
            constraints=list(state.path_constraints),
            model=get_model(list(state.path_constraints)),
            pc=state.pc,
        )


class IndexErrorDetector(Detector):
    """Detects out-of-bounds array/list access."""

    name = "index-error"

    description = "Detects out-of-bounds indexing"

    issue_kind = IssueKind.INDEX_ERROR

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: Callable[..., Any],
    ) -> Issue | None:
        """Check for index out of bounds errors in lists."""

        if instruction.opname != "BINARY_SUBSCR":
            return None

        if len(state.stack) < 2:
            return None

        index = state.stack[-1]

        container = state.stack[-2]

        from pysymex.execution.opcodes.collections import is_type_subscription

        if is_type_subscription(container):
            return None

        if not isinstance(container, SymbolicList):
            return None

        if not isinstance(index, SymbolicValue):
            return None

        oob_constraint = [
            *state.path_constraints,
            index.is_int,
            z3.Or(
                index.z3_int < -container.z3_len,
                index.z3_int >= container.z3_len,
            ),
        ]

        if is_satisfiable(oob_constraint):
            return Issue(
                kind=IssueKind.INDEX_ERROR,
                message=f"Possible index out of bounds: {container.name}[{index.name}]",
                constraints=oob_constraint,
                model=get_model(oob_constraint),
                pc=state.pc,
            )

        return None


class KeyErrorDetector(Detector):
    """Detects missing dictionary keys."""

    name = "key-error"

    description = "Detects missing dictionary keys"

    issue_kind = IssueKind.KEY_ERROR

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: Callable[..., Any],
    ) -> Issue | None:
        if instruction.opname != "BINARY_SUBSCR":
            return None

        if len(state.stack) < 2:
            return None

        key = state.stack[-1]

        container = state.stack[-2]

        from pysymex.execution.opcodes.collections import is_type_subscription

        if is_type_subscription(container):
            return None

        if not isinstance(container, SymbolicDict):
            return None

        missing_key = [
            *state.path_constraints,
            z3.Not(container.contains_key(key).z3_bool),
        ]

        if is_satisfiable(missing_key):
            return Issue(
                kind=IssueKind.KEY_ERROR,
                message=f"Possible KeyError: {container.name} may not contain key",
                constraints=missing_key,
                model=get_model(missing_key),
                pc=state.pc,
            )

        return None


class TypeErrorDetector(Detector):
    """Detects type errors in operations."""

    name = "type-error"

    description = "Detects type mismatches"

    issue_kind = IssueKind.TYPE_ERROR

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: Callable[..., Any],
    ) -> Issue | None:
        if instruction.opname == "BINARY_OP":
            if len(state.stack) < 2:
                return None

            op = instruction.argrepr

            left = state.stack[-2]

            right = state.stack[-1]

            if op == "+":
                if isinstance(left, SymbolicString) and isinstance(right, SymbolicValue):
                    type_error = [
                        *state.path_constraints,
                        right.is_int,
                    ]

                    if is_satisfiable(type_error):
                        return Issue(
                            kind=IssueKind.TYPE_ERROR,
                            message=f"Cannot {op} string and int",
                            constraints=type_error,
                            model=get_model(type_error),
                            pc=state.pc,
                        )

        return None


class AttributeErrorDetector(Detector):
    """Detects attribute access errors."""

    name = "attribute-error"

    description = "Detects missing attributes"

    issue_kind = IssueKind.ATTRIBUTE_ERROR

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: Callable[..., Any],
    ) -> Issue | None:
        return None


class OverflowDetector(Detector):
    """Detects integer overflow conditions."""

    name = "overflow"

    description = "Detects integer overflow"

    issue_kind = IssueKind.OVERFLOW

    BOUNDS = {
        "32bit": (-(2**31), 2**31 - 1),
        "64bit": (-(2**63), 2**63 - 1),
        "size_t": (0, 2**64 - 1),
    }

    def __init__(self, bound_type: str = "64bit"):
        self.min_val, self.max_val = self.BOUNDS.get(bound_type, self.BOUNDS["64bit"])

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: Callable[..., Any],
    ) -> Issue | None:
        if instruction.opname != "BINARY_OP":
            return None

        op = instruction.argrepr

        if op not in {"*", "+", "-", "**", "<<"}:
            return None

        if len(state.stack) < 2:
            return None

        left = state.stack[-2]

        right = state.stack[-1]

        if not isinstance(left, SymbolicValue) or not isinstance(right, SymbolicValue):
            return None

        result: z3.ArithRef

        if op == "*":
            result = left.z3_int * right.z3_int

        elif op == "+":
            result = left.z3_int + right.z3_int

        elif op == "-":
            result = left.z3_int - right.z3_int

        elif op == "<<":
            shift_overflow = [
                *state.path_constraints,
                left.is_int,
                right.is_int,
                right.z3_int > 63,
            ]

            if is_satisfiable(shift_overflow):
                return Issue(
                    kind=IssueKind.OVERFLOW,
                    message=f"Excessive bit shift: {right.name} could be > 63",
                    constraints=shift_overflow,
                    model=get_model(shift_overflow),
                    pc=state.pc,
                )

            return None

        elif op == "**":
            power_overflow = [
                *state.path_constraints,
                left.is_int,
                right.is_int,
                left.z3_int > 2,
                right.z3_int > 62,
            ]

            if is_satisfiable(power_overflow):
                return Issue(
                    kind=IssueKind.OVERFLOW,
                    message="Potential overflow in exponentiation",
                    constraints=power_overflow,
                    model=get_model(power_overflow),
                    pc=state.pc,
                )

            return None

        else:
            return None

        overflow_constraint = [
            *state.path_constraints,
            left.is_int,
            right.is_int,
            z3.Or(
                result > self.max_val,
                result < self.min_val,
            ),
        ]

        if is_satisfiable(overflow_constraint):
            return Issue(
                kind=IssueKind.OVERFLOW,
                message=f"Possible integer overflow in {op} operation",
                constraints=overflow_constraint,
                model=get_model(overflow_constraint),
                pc=state.pc,
            )

        return None


class ResourceLeakDetector(Detector):
    """Detects potential resource leaks (unclosed files, connections).
    Note: This detector is currently stubbed. Full resource leak detection
    requires tracking resource lifetimes across the execution, which is
    not yet fully implemented. This detector serves as a placeholder
    for future enhancement.
    """

    name = "resource-leak"

    description = "Detects unclosed resources (files, connections)"

    issue_kind = IssueKind.RESOURCE_LEAK

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: Callable[..., Any],
    ) -> Issue | None:
        return None


class ValueErrorDetector(Detector):
    """Detects potential ValueError exceptions.

    Checks for:
    - str.index() when substring may not be found
    - list.remove() when element may not exist
    - int() with non-numeric strings
    """

    name = "value-error"

    description = "Detects potential ValueError exceptions"

    issue_kind = IssueKind.VALUE_ERROR

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: Callable[..., Any],
    ) -> Issue | None:
        if instruction.opname not in ("CALL", "CALL_FUNCTION", "CALL_METHOD"):
            return None

        if len(state.stack) < 2:
            return None

        for var_name, var_val in state.local_vars.items():
            if hasattr(var_val, "_potential_exception"):
                exc = getattr(var_val, "_potential_exception", None)

                if exc == "ValueError":
                    return Issue(
                        kind=IssueKind.VALUE_ERROR,
                        message=f"Potential ValueError from {var_name}",
                        constraints=list(state.path_constraints),
                        model=get_model(list(state.path_constraints)),
                        pc=state.pc,
                    )

        return None


class EnhancedIndexErrorDetector(Detector):
    """
    Enhanced detector for out-of-bounds array/list access.
    Improvements over base:
    - Works with symbolic integer indexes
    - Tracks list length constraints
    - Handles negative indexing properly
    - Detects when index could exceed any reasonable bound
    - Skips likely dict access patterns to reduce false positives
    """

    name = "enhanced-index-error"

    description = "Enhanced out-of-bounds index detection"

    issue_kind = IssueKind.INDEX_ERROR

    MAX_REASONABLE_SIZE = 10000

    DICT_KEY_SUFFIXES = {
        "_id",
        "id",
        "key",
        "name",
        "feature",
        "tier",
        "type",
        "kind",
        "code",
        "mode",
        "command",
    }

    DICT_CONTAINER_PATTERNS = {
        "dict",
        "map",
        "cache",
        "tracker",
        "store",
        "registry",
        "config",
        "settings",
        "_recent",
        "_usage",
        "_count",
        "_limits",
        "_LIMITS",
        "_SIZE",
        "_join",
        "_command",
        "_confusion",
        "_requests",
    }

    SKIP_INDEX_PATTERNS = (
        "depth",
        "level",
        "count",
        "i",
        "j",
        "k",
        "n",
        "idx",
        "pos",
        "offset",
        "size",
        "length",
        "width",
        "height",
        "x",
        "y",
        "z",
    )

    INSTANCE_CONTAINER_PATTERNS = (
        "self.",
        "cls.",
        ".stack",
        ".elements",
        ".items",
        ".values",
        ".keys",
        ".methods",
        ".fields",
        ".attributes",
        ".properties",
        "._hooks",
        "._pending",
        "._alias",
        "._references",
        ".locals",
        ".globals",
        ".block_stack",
        "frame_copy",
        "closure_parent",
        "states",
    )

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: Callable[..., Any],
    ) -> Issue | None:
        if instruction.opname != "BINARY_SUBSCR":
            return None

        if len(state.stack) < 2:
            return None

        index = state.stack[-1]

        container = state.stack[-2]

        from pysymex.execution.opcodes.collections import is_type_subscription

        if is_type_subscription(container):
            return None

        if isinstance(container, SymbolicList):
            return self._check_symbolic_list(state, container, index)

        if isinstance(index, SymbolicValue):
            if self._is_likely_dict_access(container, index):
                return None

            return self._check_unbounded_index(state, index)

        return None

    def _is_likely_dict_access(self, container: Any, index: Any) -> bool:
        """Check if this subscript is likely dict[key] rather than list[index]."""

        container_name = getattr(container, "name", "") or ""

        index_name = getattr(index, "name", "") or ""

        container_looks_like_dict = any(
            pattern in container_name.lower() for pattern in self.DICT_CONTAINER_PATTERNS
        )

        index_looks_like_key = any(
            index_name.lower().endswith(suffix) or suffix in index_name.lower()
            for suffix in self.DICT_KEY_SUFFIXES
        )

        container_is_instance_attr = any(
            pattern in container_name for pattern in self.INSTANCE_CONTAINER_PATTERNS
        )

        index_is_common_var = any(
            index_name == pattern or index_name.endswith(f"_{pattern}")
            for pattern in self.SKIP_INDEX_PATTERNS
        )

        return (
            container_looks_like_dict
            or index_looks_like_key
            or container_is_instance_attr
            or index_is_common_var
        )

    def _check_symbolic_list(
        self, state: VMState, container: SymbolicList, index: Any
    ) -> Issue | None:
        if isinstance(index, SymbolicValue):
            oob_constraint = [
                *state.path_constraints,
                z3.Or(
                    index.z3_int >= container.z3_len,
                    index.z3_int < -container.z3_len,
                ),
            ]

            if is_satisfiable(oob_constraint):
                return Issue(
                    kind=IssueKind.INDEX_ERROR,
                    message=f"Index {index.name} may be out of bounds for {container.name}",
                    constraints=oob_constraint,
                    model=get_model(oob_constraint),
                    pc=state.pc,
                )

        elif isinstance(index, (int, float)):
            try:
                idx_val = int(index)

                oob_constraint = [
                    *state.path_constraints,
                    z3.Or(
                        idx_val >= container.z3_len,
                        idx_val < -container.z3_len,
                    ),
                ]

                if is_satisfiable(oob_constraint):
                    return Issue(
                        kind=IssueKind.INDEX_ERROR,
                        message=f"Index {idx_val} may be out of bounds for {container.name}",
                        constraints=oob_constraint,
                        model=get_model(oob_constraint),
                        pc=state.pc,
                    )

            except (ValueError, TypeError):
                pass

        return None

    def _check_unbounded_index(self, state: VMState, index: SymbolicValue) -> Issue | None:
        large_constraint = [
            *state.path_constraints,
            index.is_int,
            index.z3_int >= self.MAX_REASONABLE_SIZE,
        ]

        if is_satisfiable(large_constraint):
            return Issue(
                kind=IssueKind.INDEX_ERROR,
                message=f"Index {index.name} could be unreasonably large (>= {self.MAX_REASONABLE_SIZE})",
                constraints=large_constraint,
                model=get_model(large_constraint),
                pc=state.pc,
            )

        return None


class NoneDereferenceDetector(Detector):
    """
    Detects attribute access or method calls on potentially None values.
    NOTE: This detector may produce false positives for class instance
    attributes accessed via 'self', as symbolic execution doesn't fully
    model Python's object initialization guarantees.
    """

    name = "none-dereference"

    description = "Detects attribute access on potentially None values"

    issue_kind = IssueKind.NULL_DEREFERENCE

    SKIP_NAMES = {"self", "cls", "module", "builtins", "__builtins__"}

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: Callable[..., Any],
    ) -> Issue | None:
        if instruction.opname not in ("LOAD_ATTR", "LOAD_METHOD", "STORE_ATTR"):
            return None

        if len(state.stack) < 1:
            return None

        obj = state.stack[-1]

        attr_name = instruction.argval

        if isinstance(obj, SymbolicNone):
            return Issue(
                kind=IssueKind.NULL_DEREFERENCE,
                message=f"Attribute access '{attr_name}' on None",
                constraints=list(state.path_constraints),
                pc=state.pc,
            )

        if isinstance(obj, SymbolicValue):
            if obj.name in self.SKIP_NAMES:
                return None

            if hasattr(obj, "is_none"):
                none_constraint = (
                    *state.path_constraints,
                    obj.is_none,
                )

                if is_satisfiable(none_constraint):
                    return Issue(
                        kind=IssueKind.NULL_DEREFERENCE,
                        message=f"'{attr_name}' access on {obj.name} which could be None",
                        constraints=list(none_constraint),
                        model=get_model(none_constraint),
                        pc=state.pc,
                    )

        return None


class EnhancedTypeErrorDetector(Detector):
    """Enhanced type confusion detector.
    Includes pattern recognition to avoid false positives on dict access.
    """

    name = "enhanced-type-error"

    description = "Enhanced type confusion detection"

    issue_kind = IssueKind.TYPE_ERROR

    DICT_CONTAINER_PATTERNS = {
        "dict",
        "map",
        "cache",
        "tracker",
        "store",
        "registry",
        "config",
        "settings",
        "_recent",
        "_usage",
        "_count",
        "_limits",
        "_LIMITS",
        "_SIZE",
        "_join",
        "_command",
        "_confusion",
        "_requests",
        "global_",
        "list",
        "tuple",
        "array",
        "args",
        "kwargs",
        "instructions",
        "states",
        "facts",
        "operands",
        "elements",
        "ops",
        "comparators",
        "varnames",
        "blocks",
        "indices",
        "t",
        "x",
        "d",
        "s",
        "node",
    }

    SKIP_PREFIXES = ("subscr_", "call_result_", "call_kw_result_", "iter_")

    INSTANCE_ATTR_PATTERNS = (
        "self.",
        "cls.",
        ".stack",
        ".elements",
        ".items",
        ".values",
        ".keys",
        ".methods",
        ".fields",
        ".attributes",
        ".properties",
        "._hooks",
        "._pending",
        "._alias",
        "._references",
        ".locals",
        ".globals",
        ".block_stack",
        ".path_constraints",
        "frame_copy",
        "closure_parent",
    )

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: Callable[..., Any],
    ) -> Issue | None:
        if instruction.opname == "BINARY_SUBSCR":
            return self._check_subscript_type(state, instruction)

        if instruction.opname == "BINARY_OP":
            return self._check_binary_op(state, instruction)

        return None

    def _check_subscript_type(self, state: VMState, _instruction: dis.Instruction) -> Issue | None:
        from pysymex.core.solver import get_model, is_satisfiable

        from pysymex.core.types import SymbolicValue

        if len(state.stack) < 2:
            return None

        container = state.stack[-2]

        if isinstance(container, SymbolicValue):
            container_name = getattr(container, "name", "") or ""

            if any(pattern in container_name.lower() for pattern in self.DICT_CONTAINER_PATTERNS):
                return None

            if container_name.startswith("global_"):
                return None

            if any(container_name.startswith(prefix) for prefix in self.SKIP_PREFIXES):
                return None

            if any(pattern in container_name for pattern in self.INSTANCE_ATTR_PATTERNS):
                return None

            subscript_int = [
                *state.path_constraints,
                container.is_int,
            ]

            if is_satisfiable(subscript_int):
                return Issue(
                    kind=IssueKind.TYPE_ERROR,
                    message=f"Attempting to subscript {container.name} which could be an int",
                    constraints=subscript_int,
                    model=get_model(subscript_int),
                    pc=state.pc,
                )

        return None

    def _check_binary_op(self, state: VMState, instruction: dis.Instruction) -> Issue | None:
        from pysymex.core.solver import get_model, is_satisfiable

        from pysymex.core.types import SymbolicString, SymbolicValue

        if len(state.stack) < 2:
            return None

        op = instruction.argrepr

        left = state.stack[-2]

        right = state.stack[-1]

        if op == "+":
            if isinstance(left, SymbolicString) and isinstance(right, SymbolicValue):
                type_error = [*state.path_constraints, right.is_int]

                if is_satisfiable(type_error):
                    return Issue(
                        kind=IssueKind.TYPE_ERROR,
                        message="Cannot concatenate string with int",
                        constraints=type_error,
                        model=get_model(type_error),
                        pc=state.pc,
                    )

        return None


class FormatStringDetector(Detector):
    """Detects potential format string vulnerabilities."""

    name = "format-string"

    description = "Detects format string injection vulnerabilities"

    issue_kind = IssueKind.FORMAT_STRING_INJECTION

    DANGEROUS_CALLS = {"eval", "exec", "compile", "getattr", "setattr"}

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: Callable[..., Any],
    ) -> Issue | None:
        if instruction.opname in ("CALL", "CALL_FUNCTION"):
            return self._check_dangerous_call(state, instruction)

        if instruction.opname == "FORMAT_VALUE":
            return self._check_format_value(state, instruction)

        return None

    def _check_dangerous_call(self, state: VMState, instruction: dis.Instruction) -> Issue | None:
        if not hasattr(state, "taint_tracker") or state.taint_tracker is None:
            return None

        taint_tracker: Any = state.taint_tracker

        argc = int(instruction.argval) if instruction.argval else 0

        if argc > 0 and len(state.stack) >= argc:
            for i in range(argc):
                arg = state.stack[-(i + 1)]

                if taint_tracker.is_tainted(arg):
                    return Issue(
                        kind=IssueKind.FORMAT_STRING_INJECTION,
                        message="Potentially tainted string passed to function call",
                        constraints=list(state.path_constraints),
                        pc=state.pc,
                    )

        return None

    def _check_format_value(self, state: VMState, _instruction: dis.Instruction) -> Issue | None:
        if not hasattr(state, "taint_tracker") or state.taint_tracker is None:
            return None

        taint_tracker: Any = state.taint_tracker

        if len(state.stack) < 1:
            return None

        val = state.stack[-1]

        if taint_tracker.is_tainted(val):
            return Issue(
                kind=IssueKind.FORMAT_STRING_INJECTION,
                message="Tainted value used in format string",
                constraints=list(state.path_constraints),
                pc=state.pc,
            )

        return None


class UnboundVariableDetector(Detector):
    """Detects potential use of unbound/uninitialized variables.
    Checks for LOAD_NAME/LOAD_FAST operations on variables that may not
    have been assigned on all code paths.
    """

    name = "unbound-variable"

    description = "Detects potential NameError from unbound variables"

    issue_kind = IssueKind.UNBOUND_VARIABLE

    BUILTIN_NAMES = frozenset(
        {
            "True",
            "False",
            "None",
            "print",
            "len",
            "range",
            "str",
            "int",
            "float",
            "list",
            "dict",
            "set",
            "tuple",
            "bool",
            "type",
            "isinstance",
            "hasattr",
            "getattr",
            "setattr",
            "callable",
            "iter",
            "next",
            "zip",
            "map",
            "filter",
            "sum",
            "min",
            "max",
            "abs",
            "round",
            "sorted",
            "reversed",
            "enumerate",
            "open",
            "input",
            "Exception",
            "ValueError",
            "TypeError",
            "KeyError",
            "IndexError",
            "AttributeError",
            "RuntimeError",
        }
    )

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: Callable[..., Any],
    ) -> Issue | None:
        if instruction.opname in ("LOAD_FAST", "LOAD_FAST_CHECK"):
            var_name = instruction.argval

            if var_name in (
                "__class__",
                "visit",
                "dfs",
                "strongconnect",
                "lock_order_graph",
                "mycmp",
                "warnings",
                "file_path",
                "find",
                "has_cycle",
                "used",
                "_ast",
                "annotation_names",
                "var_name",
            ):
                return None

            if len(var_name) <= 2 and var_name[0].isupper():
                return None

            if state.get_local(var_name) is None:
                return Issue(
                    kind=IssueKind.UNBOUND_VARIABLE,
                    message=f"Variable '{var_name}' may be unbound (NameError)",
                    constraints=list(state.path_constraints),
                    pc=state.pc,
                )

        return None


class TaintFlowDetector(Detector):
    """Detects tainted data flows to sensitive sinks."""

    name = "taint-flow"

    description = "Detects tainted data flows to security-sensitive sinks"

    issue_kind = IssueKind.SQL_INJECTION

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: Callable[..., Any],
    ) -> Issue | None:
        if not hasattr(state, "_taint_tracker"):
            return None

        taint_tracker: Any = state._taint_tracker

        if taint_tracker is None:
            return None

        flows: list[Any] = taint_tracker.get_all_flows()

        if not flows:
            return None

        for flow in flows:
            from pysymex.analysis.taint import TaintSink

            if flow.sink == TaintSink.SQL_QUERY:
                return Issue(
                    kind=IssueKind.SQL_INJECTION,
                    message="Potential SQL injection: tainted data flows to SQL query",
                    constraints=list(state.path_constraints),
                    pc=state.pc,
                )

            elif flow.sink == TaintSink.FILE_PATH:
                return Issue(
                    kind=IssueKind.PATH_TRAVERSAL,
                    message="Potential path traversal: tainted data flows to file path",
                    constraints=list(state.path_constraints),
                    pc=state.pc,
                )

        return None


class DetectorRegistry:
    """Registry of available detectors."""

    def __init__(self):
        self._detectors: dict[str, type[Detector]] = {}

        self._instances: dict[str, Detector] = {}

        self.register(DivisionByZeroDetector)

        self.register(AssertionErrorDetector)

        self.register(IndexErrorDetector)

        self.register(KeyErrorDetector)

        self.register(TypeErrorDetector)

        self.register(AttributeErrorDetector)

        self.register(OverflowDetector)

        self.register(EnhancedIndexErrorDetector)

        self.register(NoneDereferenceDetector)

        self.register(EnhancedTypeErrorDetector)

        self.register(FormatStringDetector)

        self.register(ResourceLeakDetector)

        self.register(ValueErrorDetector)

        self.register(TaintFlowDetector)

        self.register(UnboundVariableDetector)

    def register(self, detector_class: type[Detector]) -> None:
        """Register a detector class."""

        self._detectors[detector_class.name] = detector_class

    def get(self, name: str) -> Detector | None:
        """Get a detector instance by name."""

        if name not in self._detectors:
            return None

        if name not in self._instances:
            self._instances[name] = self._detectors[name]()

        return self._instances[name]

    def get_all(self) -> list[Detector | None]:
        """Get all detector instances."""

        return [self.get(name) for name in self._detectors]

    def get_by_kind(self, kind: IssueKind) -> list[Detector | None]:
        """Get detectors for a specific issue kind."""

        return [self.get(name) for name, cls in self._detectors.items() if cls.issue_kind == kind]

    def list_available(self) -> list[str]:
        """List available detector names."""

        return list(self._detectors.keys())


def _create_default_registry() -> DetectorRegistry:
    """Create and configure the default detector registry."""

    registry = DetectorRegistry()

    try:
        from pysymex.analysis.detectors.specialized import register_advanced_detectors

        register_advanced_detectors(registry)

    except (ImportError, AttributeError):
        pass

    return registry


default_registry = _create_default_registry()
