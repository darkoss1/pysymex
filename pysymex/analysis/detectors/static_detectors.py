"""Concrete enhanced detector implementations.

Provides all concrete detector classes:
- StaticDivisionByZeroDetector
- StaticKeyErrorDetector
- StaticIndexErrorDetector
- StaticTypeErrorDetector
- StaticAttributeErrorDetector
- StaticAssertionErrorDetector
- DeadCodeDetector
"""

from __future__ import annotations

from pysymex.analysis.patterns import PatternKind
from pysymex.analysis.type_inference import PyType, TypeKind

from .static_types import (
    DetectionContext,
    Issue,
    IssueKind,
    StaticDetector,
)


class StaticDivisionByZeroDetector(StaticDetector):
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
        """Should check."""
        instr = ctx.instruction
        if instr.opname == "BINARY_OP":
            return instr.argrepr in self.DIVISION_ARGREPS
        return False

    def check(self, ctx: DetectionContext) -> Issue | None:
        """Check."""
        divisor_info = self._get_divisor_info(ctx)
        if divisor_info is None:
            return None
        divisor_value, divisor_var, divisor_type = divisor_info
        if divisor_type and not (
            divisor_type.is_numeric() or divisor_type.kind in (TypeKind.ANY, TypeKind.UNKNOWN)
        ):
            return None

        if divisor_value is not None:
            if not isinstance(divisor_value, (int, float, complex)):
                return None
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
    ) -> tuple[object | None, str | None, PyType | None] | None:
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
        if ctx.pattern_info is None:
            return False
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
        idx = None
        for i, instr in enumerate(instructions):
            if instr.offset == pc:
                idx = i
                break
        if idx is None:
            return False
        for i in range(idx - 1, max(0, idx - 20), -1):
            instr = instructions[i]
            if instr.opname in {
                "POP_JUMP_IF_TRUE",
                "POP_JUMP_IF_FALSE",
                "POP_JUMP_IF_NONE",
                "POP_JUMP_IF_NOT_NONE",
                "JUMP_FORWARD",
                "JUMP_BACKWARD",
                "JUMP_ABSOLUTE",
                "FOR_ITER",
            }:
                break
            if instr.opname == "LOAD_ASSERTION_ERROR":
                return True
        return False


class StaticKeyErrorDetector(StaticDetector):
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
        """Check."""
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
    ) -> tuple[str, PyType, str | None, object | None] | None:
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
        key_value: object | None,
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
        key_value: object | None,
    ) -> bool:
        """Check for prior `if key in dict:` check."""
        if ctx.pattern_info is None:
            return False
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


class StaticIndexErrorDetector(StaticDetector):
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
        """Check."""
        container_info = self._get_container_info(ctx)
        if container_info is None:
            return None
        container_var, container_type, index_var, index_value = container_info

        if container_var and container_var in {
            "list",
            "dict",
            "tuple",
            "set",
            "frozenset",
            "type",
            "bytes",
            "bytearray",
            "memoryview",
            "range",
            "slice",
            "property",
            "classmethod",
            "staticmethod",
            "super",
            "object",
            "str",
            "int",
            "float",
            "bool",
            "complex",
            "Optional",
            "Union",
            "Callable",
            "Literal",
            "Annotated",
            "ClassVar",
            "Final",
            "Type",
            "Generic",
            "Protocol",
            "ParamSpec",
            "TypeVar",
            "Sequence",
            "Mapping",
            "Iterable",
            "Iterator",
            "Any",
        }:
            return None
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
    ) -> tuple[str, PyType, str | None, object | None] | None:
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
        if ctx.pattern_info is None:
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
        idx = None
        for i, instr in enumerate(instructions):
            if instr.offset == pc:
                idx = i
                break
        if idx is None:
            return False
        for i in range(idx - 1, max(0, idx - 15), -1):
            instr = instructions[i]
            if instr.opname in {
                "POP_JUMP_IF_TRUE",
                "POP_JUMP_IF_FALSE",
                "POP_JUMP_IF_NONE",
                "POP_JUMP_IF_NOT_NONE",
                "JUMP_FORWARD",
                "JUMP_BACKWARD",
                "JUMP_ABSOLUTE",
                "FOR_ITER",
            }:
                break
            if instr.opname == "COMPARE_OP":
                return True
        return False

    def _is_safe_access_pattern(
        self,
        ctx: DetectionContext,
        container: str,
        index_var: str | None,
        index_value: object | None,
    ) -> bool:
        """Check for common safe access patterns."""
        if index_value == 0 or index_value == -1:
            container_type = ctx.get_type(container)
            if container_type.length is not None and container_type.length > 0:
                return True
        return False


class StaticTypeErrorDetector(StaticDetector):
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
        """Should check."""
        instr = ctx.instruction
        if instr.opname == "BINARY_OP":
            return True
        if instr.opname in {"CALL", "CALL_FUNCTION"}:
            return True
        if instr.opname == "LOAD_ATTR":
            return True
        return False

    def check(self, ctx: DetectionContext) -> Issue | None:
        """Check."""
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
        left_type, right_type, _left_var, _right_var = operands
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
        if func_type.kind in (TypeKind.CALLABLE, TypeKind.UNKNOWN, TypeKind.CLASS):
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

    def _type_from_value(self, value: object) -> PyType:
        """Infer type from a constant value."""
        match value:
            case None:
                return PyType.none_type()
            case bool():
                return PyType.bool_type()
            case int():
                return PyType.int_type()
            case float():
                return PyType.float_type()
            case str():
                return PyType.str_type()
            case list():
                return PyType.list_type()
            case tuple():
                return PyType.tuple_type()
            case dict():
                return PyType.dict_type()
            case set():
                return PyType.set_type()
            case _:
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


class StaticAttributeErrorDetector(StaticDetector):
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
        """Check."""
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
        if obj_type.is_optional():
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
        if ctx.pattern_info is None:
            return False
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
        if ctx.pattern_info is None:
            return False
        patterns = ctx.pattern_info.matcher.get_patterns_at(ctx.pc)
        for pattern in patterns:
            if pattern.kind == PatternKind.HASATTR_CHECK:
                return True
        return False

    def _in_optional_chain(self, ctx: DetectionContext, var_name: str) -> bool:
        """Check if in an optional chain pattern."""
        if ctx.pattern_info is None:
            return False
        patterns = ctx.pattern_info.matcher.get_patterns_at(ctx.pc)
        for pattern in patterns:
            if pattern.kind == PatternKind.OPTIONAL_CHAIN:
                if pattern.variables.get("var_name") == var_name:
                    return True
        return False


class StaticAssertionErrorDetector(StaticDetector):
    """
    Enhanced detector for assertion failures.
    Checks if assert conditions are always false.
    """

    def issue_kind(self) -> IssueKind:
        return IssueKind.ASSERTION_ERROR

    def should_check(self, ctx: DetectionContext) -> bool:
        return ctx.instruction.opname == "LOAD_ASSERTION_ERROR"

    def check(self, ctx: DetectionContext) -> Issue | None:
        """Check."""
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


class DeadCodeDetector(StaticDetector):
    """
    Detector for dead/unreachable code.
    Finds code that can never execute.
    """

    def issue_kind(self) -> IssueKind:
        return IssueKind.DEAD_CODE

    def should_check(self, ctx: DetectionContext) -> bool:
        return ctx.flow_context is not None

    def check(self, ctx: DetectionContext) -> Issue | None:
        """Check."""
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
