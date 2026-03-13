"""Core pattern types, base classes, and basic handlers for pysymex.

Provides PatternKind enum, PatternMatch dataclass, PatternHandler ABC,
and basic handlers (Dict, Iteration, isinstance, None, hasattr).
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
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum, auto

from pysymex._compat import get_starts_line

from ..type_inference import PyType, TypeEnvironment, TypeKind

_safe_line = get_starts_line


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
    KEY_CHECK = auto()
    DICT_INT_KEY = auto()


@dataclass
class PatternMatch:
    """Result of matching a pattern."""

    kind: PatternKind
    confidence: float
    start_pc: int
    end_pc: int
    line: int | None = None
    variables: dict[str, object] = field(default_factory=dict[str, object])
    type_refinements: dict[str, PyType] = field(default_factory=dict[str, PyType])
    preconditions: list[str] = field(default_factory=list[str])
    guarantees: list[str] = field(default_factory=list[str])


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
        """Pattern kinds."""
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
        arg_count = self._call_arg_count(instructions[call_idx])
        if arg_count is None:
            return None
        has_default = arg_count == 2
        return PatternMatch(
            kind=PatternKind.DICT_GET,
            confidence=0.95,
            start_pc=instr.offset,
            end_pc=instructions[call_idx].offset,
            line=_safe_line(instr),
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
        """Can raise error."""
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

    def _call_arg_count(self, instr: dis.Instruction) -> int | None:
        """Get argument count from CALL instruction.

        Handles edge cases where argval might be None but arg is set,
        or where both need to be checked for robustness.
        """

        if instr.argval is not None:
            return int(instr.argval)
        if instr.arg is not None:
            return int(instr.arg)

        if instr.opname in {"CALL", "CALL_FUNCTION", "CALL_METHOD", "CALL_KW"}:

            return 0
        return None


class DictSetdefaultHandler(PatternHandler):
    """Handles dict.setdefault(key, default) pattern."""

    def pattern_kinds(self) -> set[PatternKind]:
        """Pattern kinds."""
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
                        line=_safe_line(instr),
                        variables={"dict_var": dict_var},
                        guarantees=[
                            "never_raises_key_error",
                            "key_always_exists_after",
                        ],
                    )
        return None

    def can_raise_error(self, match: PatternMatch, error_type: str) -> bool:
        """Can raise error."""
        if error_type == "KeyError":
            return False
        return True


class DefaultDictAccessHandler(PatternHandler):
    """Handles defaultdict[key] access pattern."""

    def pattern_kinds(self) -> set[PatternKind]:
        """Pattern kinds."""
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
                    line=_safe_line(instr),
                    variables={"dict_var": var_name},
                    guarantees=[
                        "never_raises_key_error",
                        "returns_default_factory_value",
                    ],
                )
        return None

    def can_raise_error(self, match: PatternMatch, error_type: str) -> bool:
        """Can raise error."""
        if error_type == "KeyError":
            return False
        return True


class CounterAccessHandler(PatternHandler):
    """Handles Counter[key] access pattern."""

    def pattern_kinds(self) -> set[PatternKind]:
        """Pattern kinds."""
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
                    line=_safe_line(instr),
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
        """Can raise error."""
        if error_type == "KeyError":
            return False
        return True


class SafeIterationHandler(PatternHandler):
    """Handles safe iteration patterns that can't cause index errors."""

    def pattern_kinds(self) -> set[PatternKind]:
        """Pattern kinds."""
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
                        line=_safe_line(prev_instr),
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
                        line=_safe_line(instr),
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
                        line=_safe_line(instr),
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
                        line=_safe_line(instr),
                        guarantees=[
                            "safe_iteration",
                            "bounded_iteration",
                        ],
                    )
        return None

    def can_raise_error(self, match: PatternMatch, error_type: str) -> bool:
        """Can raise error."""
        if error_type == "IndexError" and "safe_iteration" in match.guarantees:
            return False
        return True


class IsinstanceHandler(PatternHandler):
    """Handles isinstance(x, T) type guard pattern."""

    def pattern_kinds(self) -> set[PatternKind]:
        """Pattern kinds."""
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
        type_refinements: dict[str, PyType] = {}
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
            line=_safe_line(instr),
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
        """Pattern kinds."""
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
                            line=_safe_line(instr),
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
                    line=_safe_line(instr),
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
        """Pattern kinds."""
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
                    line=_safe_line(instr),
                    guarantees=["attribute_check", "safe_before_access"],
                )
        return None
