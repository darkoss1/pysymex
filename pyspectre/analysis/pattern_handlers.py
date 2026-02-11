"""
Python Pattern Handlers for PySpectre.
This module provides handlers for common Python patterns that require
special analysis to avoid false positives while catching real bugs.
Patterns handled:
- Dictionary access patterns (dict.get, setdefault, defaultdict)
- Iteration patterns (enumerate, zip, items, etc.)
- Context managers (with statements)
- Exception handling patterns
- Type guard patterns (isinstance, type, callable checks)
- Collection patterns (list comprehensions, generator expressions)
- Attribute access patterns (getattr, hasattr)
- String patterns (format, join, split)
"""

from __future__ import annotations
import dis
from abc import ABC, abstractmethod
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
)
from .type_inference import PyType, TypeEnvironment, TypeKind


class PatternKind(Enum):
    """Categories of Python patterns."""

    DICT_GET = auto()
    DICT_SETDEFAULT = auto()
    DICT_POP = auto()
    DEFAULTDICT_ACCESS = auto()
    COUNTER_ACCESS = auto()
    DICT_COMPREHENSION = auto()
    ENUMERATE_ITER = auto()
    ZIP_ITER = auto()
    DICT_ITEMS_ITER = auto()
    DICT_KEYS_ITER = auto()
    DICT_VALUES_ITER = auto()
    RANGE_ITER = auto()
    ISINSTANCE_CHECK = auto()
    ISSUBCLASS_CHECK = auto()
    TYPE_CHECK = auto()
    NONE_CHECK = auto()
    CALLABLE_CHECK = auto()
    HASATTR_CHECK = auto()
    GETATTR_DEFAULT = auto()
    HASATTR_GETATTR = auto()
    LIST_APPEND = auto()
    LIST_EXTEND = auto()
    SET_ADD = auto()
    SET_DISCARD = auto()
    STRING_FORMAT = auto()
    STRING_JOIN = auto()
    STRING_SPLIT = auto()
    STRING_MULTIPLY = auto()
    TRY_EXCEPT_PATTERN = auto()
    CONTEXT_MANAGER = auto()
    TRUTHY_CHECK = auto()
    FALSY_CHECK = auto()
    OPTIONAL_CHAIN = auto()
    NULL_COALESCE = auto()
    TERNARY_NONE = auto()


@dataclass
class PatternMatch:
    """Result of matching a pattern."""

    kind: PatternKind
    confidence: float
    start_pc: int
    end_pc: int
    line: int | None = None
    variables: dict[str, Any] = field(default_factory=dict)
    type_refinements: dict[str, PyType] = field(default_factory=dict)
    preconditions: list[str] = field(default_factory=list)
    guarantees: list[str] = field(default_factory=list)


class PatternHandler(ABC):
    """Base class for pattern handlers."""

    @abstractmethod
    def pattern_kinds(self) -> set[PatternKind]:
        """Return the kinds of patterns this handler recognizes."""

    @abstractmethod
    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """
        Try to match a pattern starting at the given instruction index.
        Returns PatternMatch if pattern is recognized, None otherwise.
        """

    def can_raise_error(self, match: PatternMatch, error_type: str) -> bool:
        """
        Check if a matched pattern can raise a specific error.
        This is used to suppress false positives when we know a pattern
        is safe.
        """
        return True


class DictGetHandler(PatternHandler):
    """Handles dict.get(key, default) pattern."""

    def pattern_kinds(self) -> set[PatternKind]:
        return {PatternKind.DICT_GET}

    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """
        Match pattern:
        LOAD_FAST/NAME dict_var
        LOAD_ATTR 'get'
        LOAD_... key
        [LOAD_... default]  # optional
        CALL 1 or 2
        """
        if start_idx + 2 >= len(instructions):
            return None
        instr = instructions[start_idx]
        if instr.opname not in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            return None
        dict_var = instr.argval
        dict_type = env.get_type(dict_var)
        if dict_type.kind != TypeKind.DICT and dict_type.kind != TypeKind.UNKNOWN:
            return None
        attr_idx = self._find_load_attr(instructions, start_idx + 1, "get")
        if attr_idx < 0:
            return None
        call_idx = self._find_call(instructions, attr_idx + 1, {1, 2})
        if call_idx < 0:
            return None
        has_default = self._call_arg_count(instructions[call_idx]) == 2
        return PatternMatch(
            kind=PatternKind.DICT_GET,
            confidence=0.95,
            start_pc=instr.offset,
            end_pc=instructions[call_idx].offset,
            line=instr.starts_line,
            variables={
                "dict_var": dict_var,
                "has_default": has_default,
            },
            guarantees=[
                "never_raises_key_error",
                "returns_default_or_value",
            ],
        )

    def can_raise_error(self, match: PatternMatch, error_type: str) -> bool:
        if error_type == "KeyError":
            return False
        return True

    def _find_load_attr(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        attr_name: str,
    ) -> int:
        """Find LOAD_ATTR with given attribute name."""
        for i in range(start_idx, min(start_idx + 5, len(instructions))):
            instr = instructions[i]
            if instr.opname == "LOAD_ATTR" and instr.argval == attr_name:
                return i
        return -1

    def _find_call(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        arg_counts: set[int],
    ) -> int:
        """Find CALL instruction with specified argument count."""
        for i in range(start_idx, min(start_idx + 10, len(instructions))):
            instr = instructions[i]
            if instr.opname in {"CALL", "CALL_FUNCTION", "CALL_METHOD"}:
                if instr.argval in arg_counts or instr.arg in arg_counts:
                    return i
        return -1

    def _call_arg_count(self, instr: dis.Instruction) -> int:
        """Get argument count from CALL instruction."""
        return instr.argval if instr.argval is not None else instr.arg


class DictSetdefaultHandler(PatternHandler):
    """Handles dict.setdefault(key, default) pattern."""

    def pattern_kinds(self) -> set[PatternKind]:
        return {PatternKind.DICT_SETDEFAULT}

    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Match dict.setdefault pattern."""
        if start_idx + 2 >= len(instructions):
            return None
        instr = instructions[start_idx]
        if instr.opname not in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            return None
        dict_var = instr.argval
        for i in range(start_idx + 1, min(start_idx + 5, len(instructions))):
            if instructions[i].opname == "LOAD_ATTR":
                if instructions[i].argval == "setdefault":
                    return PatternMatch(
                        kind=PatternKind.DICT_SETDEFAULT,
                        confidence=0.95,
                        start_pc=instr.offset,
                        end_pc=instructions[i].offset,
                        line=instr.starts_line,
                        variables={"dict_var": dict_var},
                        guarantees=[
                            "never_raises_key_error",
                            "key_always_exists_after",
                        ],
                    )
        return None

    def can_raise_error(self, match: PatternMatch, error_type: str) -> bool:
        if error_type == "KeyError":
            return False
        return True


class DefaultDictAccessHandler(PatternHandler):
    """Handles defaultdict[key] access pattern."""

    def pattern_kinds(self) -> set[PatternKind]:
        return {PatternKind.DEFAULTDICT_ACCESS}

    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Match defaultdict subscript access."""
        if start_idx + 2 >= len(instructions):
            return None
        instr = instructions[start_idx]
        if instr.opname not in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            return None
        var_name = instr.argval
        var_type = env.get_type(var_name)
        if var_type.kind != TypeKind.DEFAULTDICT:
            return None
        for i in range(start_idx + 1, min(start_idx + 5, len(instructions))):
            if instructions[i].opname == "BINARY_SUBSCR":
                return PatternMatch(
                    kind=PatternKind.DEFAULTDICT_ACCESS,
                    confidence=0.99,
                    start_pc=instr.offset,
                    end_pc=instructions[i].offset,
                    line=instr.starts_line,
                    variables={"dict_var": var_name},
                    guarantees=[
                        "never_raises_key_error",
                        "returns_default_factory_value",
                    ],
                )
        return None

    def can_raise_error(self, match: PatternMatch, error_type: str) -> bool:
        if error_type == "KeyError":
            return False
        return True


class CounterAccessHandler(PatternHandler):
    """Handles Counter[key] access pattern."""

    def pattern_kinds(self) -> set[PatternKind]:
        return {PatternKind.COUNTER_ACCESS}

    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Match Counter subscript access."""
        if start_idx + 2 >= len(instructions):
            return None
        instr = instructions[start_idx]
        if instr.opname not in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            return None
        var_name = instr.argval
        var_type = env.get_type(var_name)
        if var_type.kind != TypeKind.COUNTER:
            return None
        for i in range(start_idx + 1, min(start_idx + 5, len(instructions))):
            if instructions[i].opname == "BINARY_SUBSCR":
                return PatternMatch(
                    kind=PatternKind.COUNTER_ACCESS,
                    confidence=0.99,
                    start_pc=instr.offset,
                    end_pc=instructions[i].offset,
                    line=instr.starts_line,
                    variables={"dict_var": var_name},
                    type_refinements={
                        "_result": PyType.int_type(),
                    },
                    guarantees=[
                        "never_raises_key_error",
                        "returns_zero_for_missing",
                    ],
                )
        return None

    def can_raise_error(self, match: PatternMatch, error_type: str) -> bool:
        if error_type == "KeyError":
            return False
        return True


class SafeIterationHandler(PatternHandler):
    """Handles safe iteration patterns that can't cause index errors."""

    def pattern_kinds(self) -> set[PatternKind]:
        return {
            PatternKind.ENUMERATE_ITER,
            PatternKind.ZIP_ITER,
            PatternKind.DICT_ITEMS_ITER,
            PatternKind.DICT_KEYS_ITER,
            PatternKind.DICT_VALUES_ITER,
            PatternKind.RANGE_ITER,
        }

    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Match safe iteration patterns."""
        if start_idx >= len(instructions):
            return None
        instr = instructions[start_idx]
        if instr.opname == "GET_ITER":
            return self._match_iteration_source(instructions, start_idx, env)
        return None

    def _match_iteration_source(
        self,
        instructions: Sequence[dis.Instruction],
        get_iter_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Identify the source of iteration."""
        if get_iter_idx < 1:
            return None
        prev_idx = get_iter_idx - 1
        while prev_idx >= 0:
            prev_instr = instructions[prev_idx]
            if prev_instr.opname in {"CALL", "CALL_FUNCTION"}:
                return self._identify_iterable_call(instructions, prev_idx, get_iter_idx, env)
            if prev_instr.opname == "LOAD_ATTR":
                attr = prev_instr.argval
                if attr in {"items", "keys", "values"}:
                    kind_map = {
                        "items": PatternKind.DICT_ITEMS_ITER,
                        "keys": PatternKind.DICT_KEYS_ITER,
                        "values": PatternKind.DICT_VALUES_ITER,
                    }
                    return PatternMatch(
                        kind=kind_map[attr],
                        confidence=0.9,
                        start_pc=prev_instr.offset,
                        end_pc=instructions[get_iter_idx].offset,
                        line=prev_instr.starts_line,
                        guarantees=["safe_iteration", "no_index_error"],
                    )
            prev_idx -= 1
            if prev_idx < get_iter_idx - 10:
                break
        return None

    def _identify_iterable_call(
        self,
        instructions: Sequence[dis.Instruction],
        call_idx: int,
        get_iter_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Identify calls that produce safe iterables."""
        for i in range(call_idx - 1, max(0, call_idx - 10), -1):
            instr = instructions[i]
            if instr.opname in {"LOAD_GLOBAL", "LOAD_NAME", "LOAD_BUILTIN"}:
                func_name = instr.argval
                if func_name == "enumerate":
                    return PatternMatch(
                        kind=PatternKind.ENUMERATE_ITER,
                        confidence=0.95,
                        start_pc=instr.offset,
                        end_pc=instructions[get_iter_idx].offset,
                        line=instr.starts_line,
                        guarantees=[
                            "safe_iteration",
                            "index_always_valid",
                            "yields_index_value_pairs",
                        ],
                    )
                if func_name == "zip":
                    return PatternMatch(
                        kind=PatternKind.ZIP_ITER,
                        confidence=0.95,
                        start_pc=instr.offset,
                        end_pc=instructions[get_iter_idx].offset,
                        line=instr.starts_line,
                        guarantees=[
                            "safe_iteration",
                            "stops_at_shortest",
                        ],
                    )
                if func_name == "range":
                    return PatternMatch(
                        kind=PatternKind.RANGE_ITER,
                        confidence=0.95,
                        start_pc=instr.offset,
                        end_pc=instructions[get_iter_idx].offset,
                        line=instr.starts_line,
                        guarantees=[
                            "safe_iteration",
                            "bounded_iteration",
                        ],
                    )
        return None

    def can_raise_error(self, match: PatternMatch, error_type: str) -> bool:
        if error_type == "IndexError" and "safe_iteration" in match.guarantees:
            return False
        return True


class IsinstanceHandler(PatternHandler):
    """Handles isinstance(x, T) type guard pattern."""

    def pattern_kinds(self) -> set[PatternKind]:
        return {PatternKind.ISINSTANCE_CHECK}

    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Match isinstance check pattern."""
        if start_idx + 3 >= len(instructions):
            return None
        instr = instructions[start_idx]
        if instr.opname not in {"LOAD_GLOBAL", "LOAD_NAME", "LOAD_BUILTIN"}:
            return None
        if instr.argval != "isinstance":
            return None
        var_name = None
        type_checked = None
        call_idx = -1
        for i in range(start_idx + 1, min(start_idx + 10, len(instructions))):
            check_instr = instructions[i]
            if check_instr.opname in {"LOAD_FAST", "LOAD_NAME"}:
                if var_name is None:
                    var_name = check_instr.argval
            if check_instr.opname in {"LOAD_GLOBAL", "LOAD_NAME"}:
                name = check_instr.argval
                if name in {"int", "str", "float", "bool", "list", "dict", "tuple", "set"}:
                    type_checked = name
            if check_instr.opname in {"CALL", "CALL_FUNCTION"}:
                call_idx = i
                break
        if var_name is None or call_idx < 0:
            return None
        type_refinements = {}
        if type_checked:
            type_map = {
                "int": PyType.int_type(),
                "str": PyType.str_type(),
                "float": PyType.float_type(),
                "bool": PyType.bool_type(),
                "list": PyType.list_type(),
                "dict": PyType.dict_type(),
                "tuple": PyType.tuple_type(),
                "set": PyType.set_type(),
            }
            if type_checked in type_map:
                type_refinements[var_name] = type_map[type_checked]
        return PatternMatch(
            kind=PatternKind.ISINSTANCE_CHECK,
            confidence=0.98,
            start_pc=instr.offset,
            end_pc=instructions[call_idx].offset,
            line=instr.starts_line,
            variables={
                "var_name": var_name,
                "type_checked": type_checked,
            },
            type_refinements=type_refinements,
            guarantees=["type_narrowing"],
        )


class NoneCheckHandler(PatternHandler):
    """Handles None check patterns (is None / is not None)."""

    def pattern_kinds(self) -> set[PatternKind]:
        return {PatternKind.NONE_CHECK}

    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Match None check pattern."""
        if start_idx + 2 >= len(instructions):
            return None
        instr = instructions[start_idx]
        if instr.opname not in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            return None
        var_name = instr.argval
        for i in range(start_idx + 1, min(start_idx + 5, len(instructions))):
            check_instr = instructions[i]
            if check_instr.opname == "LOAD_CONST" and check_instr.argval is None:
                if i + 1 < len(instructions):
                    is_op = instructions[i + 1]
                    if is_op.opname == "IS_OP":
                        is_not = is_op.argval == 1
                        return PatternMatch(
                            kind=PatternKind.NONE_CHECK,
                            confidence=0.99,
                            start_pc=instr.offset,
                            end_pc=is_op.offset,
                            line=instr.starts_line,
                            variables={
                                "var_name": var_name,
                                "is_not_none": is_not,
                            },
                            guarantees=["none_check", "type_narrowing"],
                        )
            if check_instr.opname in {"POP_JUMP_IF_NONE", "POP_JUMP_IF_NOT_NONE"}:
                is_not = check_instr.opname == "POP_JUMP_IF_NOT_NONE"
                return PatternMatch(
                    kind=PatternKind.NONE_CHECK,
                    confidence=0.99,
                    start_pc=instr.offset,
                    end_pc=check_instr.offset,
                    line=instr.starts_line,
                    variables={
                        "var_name": var_name,
                        "is_not_none": is_not,
                    },
                    guarantees=["none_check", "type_narrowing"],
                )
        return None


class HasattrHandler(PatternHandler):
    """Handles hasattr check patterns."""

    def pattern_kinds(self) -> set[PatternKind]:
        return {PatternKind.HASATTR_CHECK, PatternKind.HASATTR_GETATTR}

    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Match hasattr pattern."""
        if start_idx + 3 >= len(instructions):
            return None
        instr = instructions[start_idx]
        if instr.opname not in {"LOAD_GLOBAL", "LOAD_NAME", "LOAD_BUILTIN"}:
            return None
        if instr.argval != "hasattr":
            return None
        for i in range(start_idx + 1, min(start_idx + 10, len(instructions))):
            if instructions[i].opname in {"CALL", "CALL_FUNCTION"}:
                return PatternMatch(
                    kind=PatternKind.HASATTR_CHECK,
                    confidence=0.95,
                    start_pc=instr.offset,
                    end_pc=instructions[i].offset,
                    line=instr.starts_line,
                    guarantees=["attribute_check", "safe_before_access"],
                )
        return None


class StringMultiplyHandler(PatternHandler):
    """Handles string multiplication patterns (str * int)."""

    def pattern_kinds(self) -> set[PatternKind]:
        return {PatternKind.STRING_MULTIPLY}

    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Match string multiplication pattern."""
        if start_idx + 2 >= len(instructions):
            return None
        for i in range(start_idx, min(start_idx + 5, len(instructions))):
            instr = instructions[i]
            if instr.opname == "BINARY_OP" and instr.argrepr == "*":
                operand_types = self._get_operand_types(instructions, i, env)
                if operand_types:
                    left_type, right_type = operand_types
                    if (left_type.kind == TypeKind.STR and right_type.kind == TypeKind.INT) or (
                        left_type.kind == TypeKind.INT and right_type.kind == TypeKind.STR
                    ):
                        return PatternMatch(
                            kind=PatternKind.STRING_MULTIPLY,
                            confidence=0.95,
                            start_pc=instructions[start_idx].offset,
                            end_pc=instr.offset,
                            line=instructions[start_idx].starts_line,
                            type_refinements={
                                "_result": PyType.str_type(),
                            },
                            guarantees=["valid_string_multiply"],
                        )
        return None

    def _get_operand_types(
        self,
        instructions: Sequence[dis.Instruction],
        op_idx: int,
        env: TypeEnvironment,
    ) -> tuple[PyType, PyType] | None:
        """Get types of operands for a binary operation."""
        types = []
        for i in range(op_idx - 1, max(0, op_idx - 5), -1):
            instr = instructions[i]
            if instr.opname == "LOAD_CONST":
                val = instr.argval
                if isinstance(val, str):
                    types.append(PyType.str_type())
                elif isinstance(val, int):
                    types.append(PyType.int_type())
                elif isinstance(val, float):
                    types.append(PyType.float_type())
                else:
                    types.append(PyType.unknown())
            elif instr.opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
                var_type = env.get_type(instr.argval)
                types.append(var_type)
            if len(types) >= 2:
                break
        if len(types) >= 2:
            return (types[1], types[0])
        return None

    def can_raise_error(self, match: PatternMatch, error_type: str) -> bool:
        if error_type == "TypeError":
            return False
        return True


class OptionalChainHandler(PatternHandler):
    """Handles optional chaining patterns (x and x.attr)."""

    def pattern_kinds(self) -> set[PatternKind]:
        return {PatternKind.OPTIONAL_CHAIN}

    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Match x and x.attr pattern."""
        if start_idx + 3 >= len(instructions):
            return None
        instr = instructions[start_idx]
        if instr.opname not in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            return None
        var_name = instr.argval
        for i in range(start_idx + 1, min(start_idx + 3, len(instructions))):
            check_instr = instructions[i]
            if check_instr.opname in {"JUMP_IF_FALSE_OR_POP", "POP_JUMP_IF_FALSE"}:
                target_pc = check_instr.argval
                if i + 2 < len(instructions):
                    next_load = instructions[i + 1]
                    if next_load.opname in {"LOAD_FAST", "LOAD_NAME"}:
                        if next_load.argval == var_name:
                            if instructions[i + 2].opname == "LOAD_ATTR":
                                return PatternMatch(
                                    kind=PatternKind.OPTIONAL_CHAIN,
                                    confidence=0.9,
                                    start_pc=instr.offset,
                                    end_pc=instructions[i + 2].offset,
                                    line=instr.starts_line,
                                    variables={"var_name": var_name},
                                    guarantees=[
                                        "safe_attribute_access",
                                        "short_circuits_on_falsy",
                                    ],
                                )
        return None

    def can_raise_error(self, match: PatternMatch, error_type: str) -> bool:
        if error_type == "AttributeError":
            return False
        return True


class NullCoalesceHandler(PatternHandler):
    """Handles null coalesce patterns (x or default)."""

    def pattern_kinds(self) -> set[PatternKind]:
        return {PatternKind.NULL_COALESCE}

    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Match x or default pattern."""
        if start_idx + 2 >= len(instructions):
            return None
        instr = instructions[start_idx]
        if instr.opname not in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            return None
        var_name = instr.argval
        for i in range(start_idx + 1, min(start_idx + 3, len(instructions))):
            check_instr = instructions[i]
            if check_instr.opname in {"JUMP_IF_TRUE_OR_POP", "POP_JUMP_IF_TRUE"}:
                return PatternMatch(
                    kind=PatternKind.NULL_COALESCE,
                    confidence=0.9,
                    start_pc=instr.offset,
                    end_pc=check_instr.offset,
                    line=instr.starts_line,
                    variables={"var_name": var_name},
                    guarantees=[
                        "provides_default_value",
                        "result_never_none_if_default_not_none",
                    ],
                )
        return None


class SafeCollectionHandler(PatternHandler):
    """Handles safe collection operations that don't raise errors."""

    def pattern_kinds(self) -> set[PatternKind]:
        return {
            PatternKind.LIST_APPEND,
            PatternKind.LIST_EXTEND,
            PatternKind.SET_ADD,
            PatternKind.SET_DISCARD,
        }

    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Match safe collection operations."""
        if start_idx + 2 >= len(instructions):
            return None
        instr = instructions[start_idx]
        if instr.opname not in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            return None
        var_name = instr.argval
        var_type = env.get_type(var_name)
        for i in range(start_idx + 1, min(start_idx + 3, len(instructions))):
            attr_instr = instructions[i]
            if attr_instr.opname == "LOAD_ATTR":
                method = attr_instr.argval
                if var_type.kind == TypeKind.LIST and method in {"append", "extend", "insert"}:
                    kind_map = {
                        "append": PatternKind.LIST_APPEND,
                        "extend": PatternKind.LIST_EXTEND,
                    }
                    return PatternMatch(
                        kind=kind_map.get(method, PatternKind.LIST_APPEND),
                        confidence=0.95,
                        start_pc=instr.offset,
                        end_pc=attr_instr.offset,
                        line=instr.starts_line,
                        variables={"collection_var": var_name, "method": method},
                        guarantees=["safe_mutation", "no_index_error"],
                    )
                if var_type.kind == TypeKind.SET and method in {"add", "discard"}:
                    kind_map = {
                        "add": PatternKind.SET_ADD,
                        "discard": PatternKind.SET_DISCARD,
                    }
                    return PatternMatch(
                        kind=kind_map.get(method, PatternKind.SET_ADD),
                        confidence=0.95,
                        start_pc=instr.offset,
                        end_pc=attr_instr.offset,
                        line=instr.starts_line,
                        variables={"collection_var": var_name, "method": method},
                        guarantees=["safe_mutation", "no_key_error"],
                    )
        return None

    def can_raise_error(self, match: PatternMatch, error_type: str) -> bool:
        method = match.variables.get("method")
        if method == "discard" and error_type == "KeyError":
            return False
        if method in {"append", "extend", "add"} and error_type in {"IndexError", "KeyError"}:
            return False
        return True


class TryExceptHandler(PatternHandler):
    """Handles try/except patterns."""

    def pattern_kinds(self) -> set[PatternKind]:
        return {PatternKind.TRY_EXCEPT_PATTERN}

    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Match try/except blocks."""
        if start_idx >= len(instructions):
            return None
        instr = instructions[start_idx]
        if instr.opname in {"SETUP_FINALLY", "PUSH_EXC_INFO"}:
            end_pc = instr.offset
            caught_exceptions: set[str] = set()
            for i in range(start_idx + 1, min(start_idx + 50, len(instructions))):
                check_instr = instructions[i]
                end_pc = check_instr.offset
                if check_instr.opname == "CHECK_EXC_MATCH":
                    if i > 0:
                        prev = instructions[i - 1]
                        if prev.opname in {"LOAD_GLOBAL", "LOAD_NAME"}:
                            caught_exceptions.add(prev.argval)
                if check_instr.opname in {"POP_EXCEPT", "CLEANUP_THROW"}:
                    break
            return PatternMatch(
                kind=PatternKind.TRY_EXCEPT_PATTERN,
                confidence=0.95,
                start_pc=instr.offset,
                end_pc=end_pc,
                line=instr.starts_line,
                variables={"caught_exceptions": caught_exceptions},
                guarantees=["exceptions_handled"],
            )
        return None

    def can_raise_error(self, match: PatternMatch, error_type: str) -> bool:
        caught = match.variables.get("caught_exceptions", set())
        if error_type in caught:
            return False
        if "Exception" in caught or "BaseException" in caught:
            return False
        return True


class PatternRegistry:
    """Registry of all pattern handlers."""

    def __init__(self) -> None:
        self.handlers: list[PatternHandler] = []
        self._kind_to_handlers: dict[PatternKind, list[PatternHandler]] = defaultdict(list)
        self._register_default_handlers()

    def _register_default_handlers(self) -> None:
        """Register all default pattern handlers."""
        handlers = [
            DictGetHandler(),
            DictSetdefaultHandler(),
            DefaultDictAccessHandler(),
            CounterAccessHandler(),
            SafeIterationHandler(),
            IsinstanceHandler(),
            NoneCheckHandler(),
            HasattrHandler(),
            StringMultiplyHandler(),
            OptionalChainHandler(),
            NullCoalesceHandler(),
            SafeCollectionHandler(),
            TryExceptHandler(),
        ]
        for handler in handlers:
            self.register(handler)

    def register(self, handler: PatternHandler) -> None:
        """Register a pattern handler."""
        self.handlers.append(handler)
        for kind in handler.pattern_kinds():
            self._kind_to_handlers[kind].append(handler)

    def get_handlers_for_kind(self, kind: PatternKind) -> list[PatternHandler]:
        """Get handlers for a specific pattern kind."""
        return self._kind_to_handlers.get(kind, [])


class PatternMatcher:
    """
    Matches Python patterns in bytecode.
    Scans bytecode looking for recognized patterns that affect
    the analysis (e.g., safe operations, type guards).
    """

    def __init__(
        self,
        registry: PatternRegistry | None = None,
    ) -> None:
        self.registry = registry or PatternRegistry()
        self._cache: dict[int, list[PatternMatch]] = {}

    def find_patterns(
        self,
        instructions: Sequence[dis.Instruction],
        env: TypeEnvironment,
    ) -> list[PatternMatch]:
        """Find all patterns in the instruction sequence."""
        matches: list[PatternMatch] = []
        for i in range(len(instructions)):
            for handler in self.registry.handlers:
                match = handler.match(instructions, i, env)
                if match:
                    matches.append(match)
                    if match.start_pc not in self._cache:
                        self._cache[match.start_pc] = []
                    self._cache[match.start_pc].append(match)
        return matches

    def get_patterns_at(self, pc: int) -> list[PatternMatch]:
        """Get patterns covering a specific PC."""
        result = []
        for start_pc, matches in self._cache.items():
            for match in matches:
                if start_pc <= pc <= match.end_pc:
                    result.append(match)
        return result

    def can_error_occur(self, pc: int, error_type: str) -> bool:
        """
        Check if an error can occur at a PC given active patterns.
        Returns False if a pattern guarantees the error won't occur.
        """
        patterns = self.get_patterns_at(pc)
        for match in patterns:
            handlers = self.registry.get_handlers_for_kind(match.kind)
            for handler in handlers:
                if not handler.can_raise_error(match, error_type):
                    return False
        return True

    def get_type_refinements_at(self, pc: int) -> dict[str, PyType]:
        """Get type refinements from patterns at a PC."""
        patterns = self.get_patterns_at(pc)
        refinements: dict[str, PyType] = {}
        for match in patterns:
            refinements.update(match.type_refinements)
        return refinements

    def clear_cache(self) -> None:
        """Clear the pattern cache."""
        self._cache.clear()


class PatternAnalyzer:
    """
    High-level pattern analyzer for integration with the detector system.
    """

    def __init__(self) -> None:
        self.registry = PatternRegistry()
        self.matcher = PatternMatcher(self.registry)

    def analyze_function(
        self,
        code: Any,
        env: TypeEnvironment | None = None,
    ) -> FunctionPatternInfo:
        """Analyze patterns in a function."""
        instructions = list(dis.get_instructions(code))
        env = env or TypeEnvironment()
        patterns = self.matcher.find_patterns(instructions, env)
        return FunctionPatternInfo(
            patterns=patterns,
            matcher=self.matcher,
        )

    def should_suppress_error(
        self,
        pc: int,
        error_type: str,
    ) -> bool:
        """Check if an error should be suppressed at a PC."""
        return not self.matcher.can_error_occur(pc, error_type)


@dataclass
class FunctionPatternInfo:
    """Pattern analysis results for a function."""

    patterns: list[PatternMatch]
    matcher: PatternMatcher

    def get_patterns_by_kind(self, kind: PatternKind) -> list[PatternMatch]:
        """Get patterns of a specific kind."""
        return [p for p in self.patterns if p.kind == kind]

    def has_pattern(self, kind: PatternKind) -> bool:
        """Check if a pattern kind exists."""
        return any(p.kind == kind for p in self.patterns)

    def can_error_occur(self, pc: int, error_type: str) -> bool:
        """Check if error can occur at PC."""
        return self.matcher.can_error_occur(pc, error_type)

    def get_type_refinements(self, pc: int) -> dict[str, PyType]:
        """Get type refinements at PC."""
        return self.matcher.get_type_refinements_at(pc)
