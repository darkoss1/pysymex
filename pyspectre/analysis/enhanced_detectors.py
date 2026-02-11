"""
Enhanced Detectors for PySpectre.
This module provides enhanced bug detectors that integrate with:
- Type inference system
- Flow-sensitive analysis
- Pattern recognition
These detectors are designed to minimize false positives while
catching real bugs.
"""

from __future__ import annotations
import dis
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum, auto
from typing import (
    Any,
)
from .flow_sensitive import (
    FlowContext,
    FlowSensitiveAnalyzer,
)
from .pattern_handlers import (
    FunctionPatternInfo,
    PatternAnalyzer,
    PatternKind,
)
from .type_inference import (
    PyType,
    TypeAnalyzer,
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
    flow_context: FlowContext | None
    pattern_info: FunctionPatternInfo
    file_path: str
    function_name: str
    symbolic_state: Any | None = None

    def get_type(self, var_name: str) -> PyType:
        """Get type of a variable."""
        return self.type_env.get_type(var_name)

    def is_definitely_type(self, var_name: str, kind: TypeKind) -> bool:
        """Check if variable is definitely of a type."""
        var_type = self.type_env.get_type(var_name)
        return var_type.kind == kind

    def can_pattern_suppress(self, error_type: str) -> bool:
        """Check if a pattern suppresses an error at this PC."""
        return not self.pattern_info.can_error_occur(self.pc, error_type)

    def is_in_try_block(self, exception_type: str) -> bool:
        """Check if current PC is in a try block catching the exception."""
        from .pattern_handlers import PatternKind

        patterns = self.pattern_info.matcher.get_patterns_at(self.pc)
        for pattern in patterns:
            if pattern.kind == PatternKind.TRY_EXCEPT_PATTERN:
                caught = pattern.variables.get("caught_exceptions", set())
                if exception_type in caught or "Exception" in caught:
                    return True
        return False


class EnhancedDetector(ABC):
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


class EnhancedDivisionByZeroDetector(EnhancedDetector):
    """
    Enhanced detector for division by zero errors.
    Considers:
    - Constant divisors
    - Type constraints (non-zero proven by type)
    - Flow analysis (guards like `if x != 0`)
    - Loop context (divisor proven positive by iteration)
    """

    DIVISION_OPS = {"BINARY_OP"}
    DIVISION_ARGREPS = {"/", "//", "%"}

    def issue_kind(self) -> IssueKind:
        return IssueKind.DIVISION_BY_ZERO

    def should_check(self, ctx: DetectionContext) -> bool:
        instr = ctx.instruction
        if instr.opname == "BINARY_OP":
            return instr.argrepr in self.DIVISION_ARGREPS
        return False

    def check(self, ctx: DetectionContext) -> Issue | None:
        divisor_info = self._get_divisor_info(ctx)
        if divisor_info is None:
            return None
        divisor_value, divisor_var, divisor_type = divisor_info
        if divisor_value is not None:
            if divisor_value == 0:
                return self.create_issue(
                    ctx,
                    message="Division by zero: divisor is constant 0",
                    confidence=1.0,
                    explanation="The divisor is a literal 0, which will always cause a ZeroDivisionError.",
                    fix_suggestion="Check the divisor before division or use a non-zero value.",
                )
            else:
                return None
        if divisor_type and self._type_guarantees_nonzero(divisor_type):
            return None
        if divisor_var and self._is_guarded_by_zero_check(ctx, divisor_var):
            return None
        if ctx.is_in_try_block("ZeroDivisionError") or ctx.is_in_try_block("ArithmeticError"):
            issue = self.create_issue(
                ctx,
                message="Potential division by zero",
                confidence=0.4,
            )
            return self.suppress_issue(
                issue,
                (
                    ctx.type_env.analyzer.CAUGHT_BY_HANDLER
                    if hasattr(ctx.type_env, "analyzer")
                    else "Caught by exception handler"
                ),
            )
        if divisor_var and self._has_prior_assertion(ctx):
            return None
        if divisor_var:
            message = f"Potential division by zero: `{divisor_var}` may be zero"
        else:
            message = "Potential division by zero"
        return self.create_issue(
            ctx,
            message=message,
            confidence=0.7,
            explanation="The divisor could be zero at runtime, causing a ZeroDivisionError.",
            fix_suggestion="Add a check: `if divisor != 0:` before the division.",
        )

    def _get_divisor_info(
        self,
        ctx: DetectionContext,
    ) -> tuple[Any | None, str | None, PyType | None] | None:
        """Get information about the divisor."""
        pc = ctx.pc
        instructions = ctx.instructions
        idx = None
        for i, instr in enumerate(instructions):
            if instr.offset == pc:
                idx = i
                break
        if idx is None or idx < 1:
            return None
        prev_instr = instructions[idx - 1]
        if prev_instr.opname == "LOAD_CONST":
            return (prev_instr.argval, None, None)
        if prev_instr.opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            var_name = prev_instr.argval
            var_type = ctx.get_type(var_name)
            return (None, var_name, var_type)
        return (None, None, None)

    def _type_guarantees_nonzero(self, var_type: PyType) -> bool:
        """Check if type guarantees non-zero value."""
        if var_type.kind == TypeKind.BOOL:
            return False
        for constraint in var_type.value_constraints:
            if "> 0" in str(constraint) or ">= 1" in str(constraint):
                return True
        return False

    def _is_guarded_by_zero_check(
        self,
        ctx: DetectionContext,
        var_name: str,
    ) -> bool:
        """Check if variable is guarded by a zero check."""
        patterns = ctx.pattern_info.matcher.get_patterns_at(ctx.pc)
        for pattern in patterns:
            if pattern.kind == PatternKind.TRUTHY_CHECK:
                if pattern.variables.get("var_name") == var_name:
                    return True
        return False

    def _has_prior_assertion(
        self,
        ctx: DetectionContext,
    ) -> bool:
        """Check for prior assertion about the variable."""
        pc = ctx.pc
        instructions = ctx.instructions
        for i, instr in enumerate(instructions):
            if instr.offset >= pc:
                break
            if instr.opname == "LOAD_ASSERTION_ERROR":
                return True
        return False


class EnhancedKeyErrorDetector(EnhancedDetector):
    """
    Enhanced detector for KeyError.
    Considers:
    - defaultdict (never raises KeyError)
    - Counter (returns 0 for missing)
    - dict.get(), dict.setdefault() patterns
    - Prior key existence checks
    - Iteration patterns (dict.items(), etc.)
    """

    def issue_kind(self) -> IssueKind:
        return IssueKind.KEY_ERROR

    def should_check(self, ctx: DetectionContext) -> bool:
        return ctx.instruction.opname == "BINARY_SUBSCR"

    def check(self, ctx: DetectionContext) -> Issue | None:
        container_info = self._get_container_info(ctx)
        if container_info is None:
            return None
        container_var, container_type, key_var, key_value = container_info
        if container_type.kind not in {
            TypeKind.DICT,
            TypeKind.DEFAULTDICT,
            TypeKind.COUNTER,
            TypeKind.ORDERED_DICT,
            TypeKind.CHAIN_MAP,
            TypeKind.UNKNOWN,
        }:
            return None
        if container_type.kind == TypeKind.DEFAULTDICT:
            return None
        if container_type.kind == TypeKind.COUNTER:
            return None
        if ctx.can_pattern_suppress("KeyError"):
            return None
        if self._key_known_to_exist(ctx, container_var, key_var, key_value):
            return None
        if ctx.is_in_try_block("KeyError"):
            issue = self.create_issue(
                ctx,
                message=f"Potential KeyError accessing `{container_var}`",
                confidence=0.3,
            )
            return self.suppress_issue(
                issue,
                (
                    ctx.type_env.analyzer.CAUGHT_BY_HANDLER
                    if hasattr(ctx.type_env, "analyzer")
                    else "Caught by exception handler"
                ),
            )
        if self._has_key_check(ctx, container_var, key_var, key_value):
            return None
        if key_value is not None:
            message = f"Potential KeyError: key `{key_value}` may not exist in `{container_var}`"
        elif key_var:
            message = f"Potential KeyError: `{key_var}` may not be a key in `{container_var}`"
        else:
            message = f"Potential KeyError accessing `{container_var}`"
        return self.create_issue(
            ctx,
            message=message,
            confidence=0.6,
            explanation="Dictionary access may raise KeyError if key doesn't exist.",
            fix_suggestion="Use `dict.get(key, default)` or check `if key in dict:` first.",
        )

    def _get_container_info(
        self,
        ctx: DetectionContext,
    ) -> tuple[str, PyType, str | None, Any | None] | None:
        """Get information about the container and key."""
        pc = ctx.pc
        instructions = ctx.instructions
        idx = None
        for i, instr in enumerate(instructions):
            if instr.offset == pc:
                idx = i
                break
        if idx is None or idx < 2:
            return None
        container_var = None
        container_type = PyType.unknown()
        key_var = None
        key_value = None
        prev = instructions[idx - 1]
        if prev.opname == "LOAD_CONST":
            key_value = prev.argval
        elif prev.opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            key_var = prev.argval
        for i in range(idx - 2, max(0, idx - 10), -1):
            instr = instructions[i]
            if instr.opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
                container_var = instr.argval
                container_type = ctx.get_type(container_var)
                break
        if container_var is None:
            return None
        return (container_var, container_type, key_var, key_value)

    def _key_known_to_exist(
        self,
        ctx: DetectionContext,
        container: str,
        key_var: str | None,
        key_value: Any | None,
    ) -> bool:
        """Check if key is known to exist in the container."""
        container_type = ctx.get_type(container)
        if container_type.known_keys and key_value is not None:
            if key_value in container_type.known_keys:
                return True
        return False

    def _has_key_check(
        self,
        ctx: DetectionContext,
        container_var: str,
        key_var: str | None,
        key_value: Any | None,
    ) -> bool:
        """Check for prior `if key in dict:` check."""
        patterns = ctx.pattern_info.matcher.get_patterns_at(ctx.pc)
        for pattern in patterns:
            if pattern.kind == PatternKind.KEY_CHECK:
                checked_container = pattern.variables.get("container")
                checked_key = pattern.variables.get("key")
                if checked_container == container_var:
                    if (key_var and checked_key == key_var) or (
                        key_value is not None and checked_key == key_value
                    ):
                        return True
        return False


class EnhancedIndexErrorDetector(EnhancedDetector):
    """
    Enhanced detector for IndexError.
    Considers:
    - List/tuple bounds from type info
    - Safe iteration patterns (enumerate, zip, range)
    - Prior length checks
    - Negative indexing (which is often valid)
    """

    def issue_kind(self) -> IssueKind:
        return IssueKind.INDEX_ERROR

    def should_check(self, ctx: DetectionContext) -> bool:
        return ctx.instruction.opname == "BINARY_SUBSCR"

    def check(self, ctx: DetectionContext) -> Issue | None:
        container_info = self._get_container_info(ctx)
        if container_info is None:
            return None
        container_var, container_type, index_var, index_value = container_info
        if container_type.kind not in {
            TypeKind.LIST,
            TypeKind.TUPLE,
            TypeKind.STR,
            TypeKind.BYTES,
            TypeKind.SEQUENCE,
            TypeKind.UNKNOWN,
        }:
            return None
        if ctx.can_pattern_suppress("IndexError"):
            return None
        if self._in_safe_iteration(ctx, container_var, index_var):
            return None
        if index_value is not None and container_type.length is not None:
            if 0 <= index_value < container_type.length or (
                index_value < 0 and abs(index_value) <= container_type.length
            ):
                return None
        if self._has_bounds_check(ctx):
            return None
        if ctx.is_in_try_block("IndexError"):
            issue = self.create_issue(
                ctx,
                message=f"Potential IndexError accessing `{container_var}`",
                confidence=0.3,
            )
            return self.suppress_issue(
                issue,
                (
                    ctx.type_env.analyzer.CAUGHT_BY_HANDLER
                    if hasattr(ctx.type_env, "analyzer")
                    else "Caught by exception handler"
                ),
            )
        if self._is_safe_access_pattern(ctx, container_var, index_var, index_value):
            return None
        if index_value is not None:
            message = f"Potential IndexError: index {index_value} may be out of bounds for `{container_var}`"
        else:
            message = (
                f"Potential IndexError: `{index_var}` may be out of bounds for `{container_var}`"
            )
        return self.create_issue(
            ctx,
            message=message,
            confidence=0.5,
            explanation="List/tuple index may be out of bounds at runtime.",
            fix_suggestion="Check `if index < len(collection):` or use try/except.",
        )

    def _get_container_info(
        self,
        ctx: DetectionContext,
    ) -> tuple[str, PyType, str | None, Any | None] | None:
        """Get information about container and index."""
        pc = ctx.pc
        instructions = ctx.instructions
        idx = None
        for i, instr in enumerate(instructions):
            if instr.offset == pc:
                idx = i
                break
        if idx is None or idx < 2:
            return None
        container_var = None
        container_type = PyType.unknown()
        index_var = None
        index_value = None
        prev = instructions[idx - 1]
        if prev.opname == "LOAD_CONST":
            index_value = prev.argval
        elif prev.opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            index_var = prev.argval
        for i in range(idx - 2, max(0, idx - 10), -1):
            instr = instructions[i]
            if instr.opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
                container_var = instr.argval
                container_type = ctx.get_type(container_var)
                break

        if container_var is None:
            return None
        return (container_var, container_type, index_var, index_value)

    def _in_safe_iteration(
        self,
        ctx: DetectionContext,
        container: str,
        index_var: str | None,
    ) -> bool:
        """Check if we're in a safe iteration pattern."""
        if not index_var:
            return False
        patterns = ctx.pattern_info.patterns
        for pattern in patterns:
            if pattern.kind in {
                PatternKind.ENUMERATE_ITER,
                PatternKind.RANGE_ITER,
                PatternKind.ZIP_ITER,
            }:
                return True
        return False

    def _has_bounds_check(
        self,
        ctx: DetectionContext,
    ) -> bool:
        """Check for prior bounds checking."""
        pc = ctx.pc
        instructions = ctx.instructions
        for instr in instructions:
            if instr.offset >= pc:
                break
            if instr.opname == "COMPARE_OP":
                return True
        return False

    def _is_safe_access_pattern(
        self,
        ctx: DetectionContext,
        container: str,
        index_var: str | None,
        index_value: Any | None,
    ) -> bool:
        """Check for common safe access patterns."""
        if index_value == 0 or index_value == -1:
            container_type = ctx.get_type(container)
            if container_type.length is not None and container_type.length > 0:
                return True
        return False


class EnhancedTypeErrorDetector(EnhancedDetector):
    """
    Enhanced detector for TypeError.
    Considers:
    - Type inference for operation compatibility
    - String multiplication (str * int is valid)
    - isinstance checks that narrow type
    - Union types and overloads
    """

    def issue_kind(self) -> IssueKind:
        return IssueKind.TYPE_ERROR

    def should_check(self, ctx: DetectionContext) -> bool:
        instr = ctx.instruction
        if instr.opname == "BINARY_OP":
            return True
        if instr.opname in {"CALL", "CALL_FUNCTION"}:
            return True
        if instr.opname == "LOAD_ATTR":
            return True
        return False

    def check(self, ctx: DetectionContext) -> Issue | None:
        instr = ctx.instruction
        if instr.opname == "BINARY_OP":
            return self._check_binary_op(ctx)
        elif instr.opname in {"CALL", "CALL_FUNCTION"}:
            return self._check_call(ctx)
        elif instr.opname == "LOAD_ATTR":
            return self._check_attribute(ctx)
        return None

    def _check_binary_op(self, ctx: DetectionContext) -> Issue | None:
        """Check binary operation for type errors."""
        instr = ctx.instruction
        op = instr.argrepr
        operands = self._get_binary_operands(ctx)
        if operands is None:
            return None
        left_type, right_type, left_var, right_var = operands
        if ctx.can_pattern_suppress("TypeError"):
            return None
        if self._is_valid_binary_op(op, left_type, right_type):
            return None
        message = f"TypeError: unsupported operand types for '{op}': `{left_type.kind.name}` and `{right_type.kind.name}`"
        return self.create_issue(
            ctx,
            message=message,
            confidence=0.8,
        )

    def _check_call(self, ctx: DetectionContext) -> Issue | None:
        """Check function call for type errors."""
        func_info = self._get_function_info(ctx)
        if func_info is None:
            return None
        func_name, func_type = func_info
        if func_type.kind == TypeKind.CALLABLE or func_type.kind == TypeKind.UNKNOWN:
            return None
        return self.create_issue(
            ctx,
            message=f"TypeError: `{func_name}` of type `{func_type.kind.name}` is not callable",
            confidence=0.7,
        )

    def _check_attribute(self, ctx: DetectionContext) -> Issue | None:
        """Check attribute access for type errors."""
        instr = ctx.instruction
        attr_name = instr.argval
        obj_info = self._get_object_info(ctx)
        if obj_info is None:
            return None
        obj_var, obj_type = obj_info
        if obj_type.kind == TypeKind.NONE:
            return self.create_issue(
                ctx,
                message=f"AttributeError: 'NoneType' object has no attribute '{attr_name}'",
                confidence=0.95,
            )
        if ctx.can_pattern_suppress("AttributeError"):
            return None
        if obj_type.kind != TypeKind.UNKNOWN:
            if not self._type_has_attribute(obj_type, attr_name):
                return self.create_issue(
                    ctx,
                    message=f"AttributeError: `{obj_var}` of type `{obj_type.kind.name}` may not have attribute '{attr_name}'",
                    confidence=0.6,
                )
        return None

    def _get_binary_operands(
        self,
        ctx: DetectionContext,
    ) -> tuple[PyType, PyType, str | None, str | None] | None:
        """Get types of binary operation operands."""
        pc = ctx.pc
        instructions = ctx.instructions
        idx = None
        for i, instr in enumerate(instructions):
            if instr.offset == pc:
                idx = i
                break
        if idx is None or idx < 2:
            return None
        left_type = PyType.unknown()
        right_type = PyType.unknown()
        left_var = None
        right_var = None
        prev = instructions[idx - 1]
        if prev.opname == "LOAD_CONST":
            right_type = self._type_from_value(prev.argval)
        elif prev.opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            right_var = prev.argval
            right_type = ctx.get_type(right_var)
        for i in range(idx - 2, max(0, idx - 5), -1):
            instr = instructions[i]
            if instr.opname == "LOAD_CONST":
                left_type = self._type_from_value(instr.argval)
                break
            elif instr.opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
                left_var = instr.argval
                left_type = ctx.get_type(left_var)
                break
        return (left_type, right_type, left_var, right_var)

    def _type_from_value(self, value: Any) -> PyType:
        """Infer type from a constant value."""
        if value is None:
            return PyType.none_type()
        elif isinstance(value, bool):
            return PyType.bool_type()
        elif isinstance(value, int):
            return PyType.int_type()
        elif isinstance(value, float):
            return PyType.float_type()
        elif isinstance(value, str):
            return PyType.str_type()
        elif isinstance(value, (list, tuple)):
            if isinstance(value, list):
                return PyType.list_type()
            return PyType.tuple_type()
        elif isinstance(value, dict):
            return PyType.dict_type()
        elif isinstance(value, set):
            return PyType.set_type()
        return PyType.unknown()

    def _is_valid_binary_op(
        self,
        op: str,
        left: PyType,
        right: PyType,
    ) -> bool:
        """Check if binary operation is valid for the types."""
        if left.kind == TypeKind.UNKNOWN or right.kind == TypeKind.UNKNOWN:
            return True
        numeric_kinds = {TypeKind.INT, TypeKind.FLOAT, TypeKind.BOOL}
        if left.kind in numeric_kinds and right.kind in numeric_kinds:
            return True
        if op == "+":
            if left.kind == TypeKind.STR and right.kind == TypeKind.STR:
                return True
        if op == "*":
            if (left.kind == TypeKind.STR and right.kind == TypeKind.INT) or (
                left.kind == TypeKind.INT and right.kind == TypeKind.STR
            ):
                return True
            if (left.kind == TypeKind.LIST and right.kind == TypeKind.INT) or (
                left.kind == TypeKind.INT and right.kind == TypeKind.LIST
            ):
                return True
        if op == "+":
            if left.kind == TypeKind.LIST and right.kind == TypeKind.LIST:
                return True
            if left.kind == TypeKind.TUPLE and right.kind == TypeKind.TUPLE:
                return True
        if op in {"<", ">", "<=", ">=", "==", "!="}:
            return True
        return False

    def _get_function_info(
        self,
        ctx: DetectionContext,
    ) -> tuple[str, PyType] | None:
        """Get information about function being called."""
        pc = ctx.pc
        instructions = ctx.instructions
        idx = None
        for i, instr in enumerate(instructions):
            if instr.offset == pc:
                idx = i
                break
        if idx is None:
            return None
        for i in range(idx - 1, max(0, idx - 10), -1):
            instr = instructions[i]
            if instr.opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
                func_name = instr.argval
                func_type = ctx.get_type(func_name)
                return (func_name, func_type)
        return None

    def _get_object_info(
        self,
        ctx: DetectionContext,
    ) -> tuple[str, PyType] | None:
        """Get information about object for attribute access."""
        pc = ctx.pc
        instructions = ctx.instructions
        idx = None
        for i, instr in enumerate(instructions):
            if instr.offset == pc:
                idx = i
                break
        if idx is None or idx < 1:
            return None
        prev = instructions[idx - 1]
        if prev.opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            obj_name = prev.argval
            obj_type = ctx.get_type(obj_name)
            return (obj_name, obj_type)
        return None

    def _type_has_attribute(self, obj_type: PyType, attr: str) -> bool:
        """Check if a type has an attribute."""
        type_attrs: dict[TypeKind, set[str]] = {
            TypeKind.STR: {
                "upper",
                "lower",
                "strip",
                "split",
                "join",
                "format",
                "replace",
                "find",
                "index",
                "startswith",
                "endswith",
                "isdigit",
                "isalpha",
                "encode",
                "decode",
            },
            TypeKind.LIST: {
                "append",
                "extend",
                "insert",
                "remove",
                "pop",
                "clear",
                "index",
                "count",
                "sort",
                "reverse",
                "copy",
            },
            TypeKind.DICT: {
                "keys",
                "values",
                "items",
                "get",
                "pop",
                "update",
                "setdefault",
                "clear",
                "copy",
                "fromkeys",
            },
            TypeKind.SET: {
                "add",
                "remove",
                "discard",
                "pop",
                "clear",
                "copy",
                "union",
                "intersection",
                "difference",
                "symmetric_difference",
                "update",
                "issubset",
                "issuperset",
            },
        }
        if obj_type.kind in type_attrs:
            return attr in type_attrs[obj_type.kind]
        return True


class EnhancedAttributeErrorDetector(EnhancedDetector):
    """
    Enhanced detector for AttributeError.
    Considers:
    - None checks before attribute access
    - hasattr patterns
    - Optional chaining (x and x.attr)
    - Type narrowing from isinstance
    """

    def issue_kind(self) -> IssueKind:
        return IssueKind.ATTRIBUTE_ERROR

    def should_check(self, ctx: DetectionContext) -> bool:
        return ctx.instruction.opname == "LOAD_ATTR"

    def check(self, ctx: DetectionContext) -> Issue | None:
        instr = ctx.instruction
        attr_name = instr.argval
        obj_info = self._get_object_info(ctx)
        if obj_info is None:
            return None
        obj_var, obj_type = obj_info
        if obj_type.kind == TypeKind.NONE:
            return self.create_issue(
                ctx,
                message=f"AttributeError: 'NoneType' object has no attribute '{attr_name}'",
                confidence=0.98,
            )
        if obj_type.is_optional:
            if self._has_none_check(ctx, obj_var):
                return None
            return self.create_issue(
                ctx,
                message=f"Potential AttributeError: `{obj_var}` may be None when accessing '.{attr_name}'",
                confidence=0.7,
                fix_suggestion=f"Add `if {obj_var} is not None:` check before accessing attribute.",
            )
        if ctx.can_pattern_suppress("AttributeError"):
            return None
        if self._has_hasattr_check(ctx, obj_var, attr_name):
            return None
        if self._in_optional_chain(ctx, obj_var):
            return None
        if ctx.is_in_try_block("AttributeError"):
            issue = self.create_issue(
                ctx,
                message=f"Potential AttributeError on `{obj_var}.{attr_name}`",
                confidence=0.3,
            )
            return self.suppress_issue(issue, "Caught by exception handler")
        return None

    def _get_object_info(
        self,
        ctx: DetectionContext,
    ) -> tuple[str, PyType] | None:
        """Get info about object being accessed."""
        pc = ctx.pc
        instructions = ctx.instructions
        idx = None
        for i, instr in enumerate(instructions):
            if instr.offset == pc:
                idx = i
                break
        if idx is None or idx < 1:
            return None
        prev = instructions[idx - 1]
        if prev.opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            return (prev.argval, ctx.get_type(prev.argval))
        return None

    def _has_none_check(self, ctx: DetectionContext, var_name: str) -> bool:
        """Check for prior None check on variable."""
        patterns = ctx.pattern_info.matcher.get_patterns_at(ctx.pc)
        for pattern in patterns:
            if pattern.kind == PatternKind.NONE_CHECK:
                if pattern.variables.get("var_name") == var_name:
                    if pattern.variables.get("is_not_none", False):
                        return True
        return False

    def _has_hasattr_check(
        self,
        ctx: DetectionContext,
        var_name: str,
        attr_name: str,
    ) -> bool:
        """Check for prior hasattr check."""
        patterns = ctx.pattern_info.matcher.get_patterns_at(ctx.pc)
        for pattern in patterns:
            if pattern.kind == PatternKind.HASATTR_CHECK:
                return True
        return False

    def _in_optional_chain(self, ctx: DetectionContext, var_name: str) -> bool:
        """Check if in an optional chain pattern."""
        patterns = ctx.pattern_info.matcher.get_patterns_at(ctx.pc)
        for pattern in patterns:
            if pattern.kind == PatternKind.OPTIONAL_CHAIN:
                if pattern.variables.get("var_name") == var_name:
                    return True
        return False


class EnhancedAssertionErrorDetector(EnhancedDetector):
    """
    Enhanced detector for assertion failures.
    Checks if assert conditions are always false.
    """

    def issue_kind(self) -> IssueKind:
        return IssueKind.ASSERTION_ERROR

    def should_check(self, ctx: DetectionContext) -> bool:
        return ctx.instruction.opname == "LOAD_ASSERTION_ERROR"

    def check(self, ctx: DetectionContext) -> Issue | None:
        condition_info = self._get_assertion_condition(ctx)
        if condition_info:
            condition_text, is_always_false = condition_info
            if is_always_false:
                return self.create_issue(
                    ctx,
                    message=f"Assertion always fails: `{condition_text}`",
                    confidence=0.95,
                )
        return None

    def _get_assertion_condition(
        self,
        ctx: DetectionContext,
    ) -> tuple[str, bool] | None:
        """Get the assertion condition and check if always false."""
        pc = ctx.pc
        instructions = ctx.instructions
        idx = None
        for i, instr in enumerate(instructions):
            if instr.offset == pc:
                idx = i
                break
        if idx is None:
            return None
        for i in range(idx - 1, max(0, idx - 10), -1):
            instr = instructions[i]
            if instr.opname == "LOAD_CONST":
                if instr.argval is False:
                    return ("False", True)
            if instr.opname == "POP_JUMP_IF_TRUE":
                break
        return None


class DeadCodeDetector(EnhancedDetector):
    """
    Detector for dead/unreachable code.
    Finds code that can never execute.
    """

    def issue_kind(self) -> IssueKind:
        return IssueKind.DEAD_CODE

    def should_check(self, ctx: DetectionContext) -> bool:
        return ctx.flow_context is not None

    def check(self, ctx: DetectionContext) -> Issue | None:
        if ctx.flow_context is None:
            return None
        if ctx.flow_context.block:
            block_id = ctx.flow_context.block.id
            if not ctx.flow_context.analyzer.cfg.is_reachable(block_id):
                return self.create_issue(
                    ctx,
                    message="Unreachable code",
                    confidence=0.9,
                    explanation="This code can never be executed.",
                )
        return None


class DetectorRegistry:
    """Registry of all enhanced detectors."""

    def __init__(self) -> None:
        self.detectors: list[EnhancedDetector] = []
        self._register_default_detectors()

    def _register_default_detectors(self) -> None:
        """Register all default detectors."""
        self.register(EnhancedDivisionByZeroDetector())
        self.register(EnhancedKeyErrorDetector())
        self.register(EnhancedIndexErrorDetector())
        self.register(EnhancedTypeErrorDetector())
        self.register(EnhancedAttributeErrorDetector())
        self.register(EnhancedAssertionErrorDetector())
        self.register(DeadCodeDetector())

    def register(self, detector: EnhancedDetector) -> None:
        """Register a detector."""
        self.detectors.append(detector)

    def get_all(self) -> list[EnhancedDetector]:
        """Get all registered detectors."""
        return list(self.detectors)


class EnhancedAnalyzer:
    """
    Enhanced analyzer that integrates all detection systems.
    """

    def __init__(self) -> None:
        self.registry = DetectorRegistry()
        self.type_analyzer = TypeAnalyzer()
        self.pattern_analyzer = PatternAnalyzer()
        self.CAUGHT_BY_HANDLER = "Caught by exception handler"

    def analyze_function(
        self,
        code: Any,
        file_path: str = "<unknown>",
        type_env: TypeEnvironment | dict[int, TypeEnvironment] | None = None,
        pattern_info: FunctionPatternInfo | None = None,
        flow_analyzer: FlowSensitiveAnalyzer | None = None,
    ) -> list[Issue]:
        """Analyze a function for issues."""
        issues: list[Issue] = []
        instructions = list(dis.get_instructions(code))
        if not instructions:
            return issues

        type_data = type_env if type_env is not None else self.type_analyzer.analyze_function(code)

        def get_env_at(pc: int) -> TypeEnvironment:
            if isinstance(type_data, dict):
                return type_data.get(pc, TypeEnvironment())
            return type_data

        if pattern_info is None:
            pattern_info = self.pattern_analyzer.analyze_function(code, get_env_at(0))

        if flow_analyzer is None:
            try:
                flow_analyzer = FlowSensitiveAnalyzer(code)
            except Exception:
                pass

        for instr in instructions:
            line_no = self._extract_line_number(instr, code)
            if line_no is None:
                continue

            ctx = self._create_detection_context(
                code,
                instructions,
                instr,
                line_no,
                get_env_at(instr.offset),
                flow_analyzer,
                pattern_info,
                file_path,
            )
            issues.extend(self._run_detectors(ctx))
        return issues

    def _extract_line_number(self, instr: dis.Instruction, code: Any) -> int | None:
        """Extract line number from instruction."""
        is_start = instr.starts_line
        if is_start is None or is_start is False:
            return None

        if type(is_start) is int:
            return is_start
        if hasattr(instr, "positions") and instr.positions and instr.positions.lineno:
            return instr.positions.lineno
        return code.co_firstlineno

    def _create_detection_context(
        self,
        code: Any,
        instructions: list[dis.Instruction],
        instr: dis.Instruction,
        line_no: int,
        env: TypeEnvironment,
        flow_analyzer: FlowSensitiveAnalyzer | None,
        pattern_info: FunctionPatternInfo,
        file_path: str,
    ) -> DetectionContext:
        """Create detection context for an instruction."""
        flow_context = FlowContext.create(flow_analyzer, instr.offset) if flow_analyzer else None
        return DetectionContext(
            code=code,
            instructions=instructions,
            pc=instr.offset,
            instruction=instr,
            line=line_no,
            type_env=env,
            flow_context=flow_context,
            pattern_info=pattern_info,
            file_path=file_path,
            function_name=code.co_name,
        )

    def _run_detectors(self, ctx: DetectionContext) -> list[Issue]:
        """Run all registered detectors for a context."""
        issues = []
        for detector in self.registry.get_all():
            if detector.should_check(ctx):
                issue = detector.check(ctx)
                if issue and not issue.is_suppressed():
                    issues.append(issue)
        return issues
