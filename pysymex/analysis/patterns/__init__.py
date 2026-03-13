"""
Python Pattern Handlers for PySyMex — hub module.

Remaining handlers (StringMultiply, OptionalChain, NullCoalesce,
SafeCollection, TryExcept) plus PatternRegistry, PatternMatcher,
PatternAnalyzer, FunctionPatternInfo.

Re-exports all symbols from pattern_handlers_core for backward compatibility.
"""

from __future__ import annotations

import dis
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from typing import (
    Any,
)

from pysymex._compat import get_starts_line
from pysymex.analysis.patterns.core import (
    CounterAccessHandler,
    DefaultDictAccessHandler,
    DictGetHandler,
    DictSetdefaultHandler,
    HasattrHandler,
    IsinstanceHandler,
    NoneCheckHandler,
    PatternHandler,
    PatternKind,
    PatternMatch,
    SafeIterationHandler,
)
from pysymex.core.instruction_cache import get_instructions as _cached_get_instructions

from ..type_inference import PyType, TypeEnvironment, TypeKind

_safe_line = get_starts_line


class StringMultiplyHandler(PatternHandler):
    """Handles string multiplication patterns (str * int)."""

    def pattern_kinds(self) -> set[PatternKind]:
        """Pattern kinds."""
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
                            line=_safe_line(instructions[start_idx]),
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
        types: list[PyType] = []
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
        """Can raise error."""
        if error_type == "TypeError":
            return False
        return True


class OptionalChainHandler(PatternHandler):
    """Handles optional chaining patterns (x and x.attr)."""

    def pattern_kinds(self) -> set[PatternKind]:
        """Pattern kinds."""
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
                                    line=_safe_line(instr),
                                    variables={"var_name": var_name},
                                    guarantees=[
                                        "safe_attribute_access",
                                        "short_circuits_on_falsy",
                                    ],
                                )
        return None

    def can_raise_error(self, match: PatternMatch, error_type: str) -> bool:
        """Can raise error."""
        if error_type == "AttributeError":
            return False
        return True


class NullCoalesceHandler(PatternHandler):
    """Handles null coalesce patterns (x or default)."""

    def pattern_kinds(self) -> set[PatternKind]:
        """Pattern kinds."""
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
                    line=_safe_line(instr),
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
        """Pattern kinds."""
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
                        line=_safe_line(instr),
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
                        line=_safe_line(instr),
                        variables={"collection_var": var_name, "method": method},
                        guarantees=["safe_mutation", "no_key_error"],
                    )
        return None

    def can_raise_error(self, match: PatternMatch, error_type: str) -> bool:
        """Can raise error."""
        method = match.variables.get("method")
        if method == "discard" and error_type == "KeyError":
            return False
        if method in {"append", "extend", "add"} and error_type in {"IndexError", "KeyError"}:
            return False
        return True


class TryExceptHandler(PatternHandler):
    """Handles try/except patterns."""

    def pattern_kinds(self) -> set[PatternKind]:
        """Pattern kinds."""
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
                line=_safe_line(instr),
                variables={"caught_exceptions": caught_exceptions},
                guarantees=["exceptions_handled"],
            )
        return None

    def can_raise_error(self, match: PatternMatch, error_type: str) -> bool:
        """Can raise error."""
        caught = match.variables.get("caught_exceptions", set())
        if error_type in caught:
            return False
        if "Exception" in caught or "BaseException" in caught:
            return False
        return True


class PatternRegistry:
    """Registry of all pattern handlers."""

    def __init__(self) -> None:
        """Init."""
        """Initialize the class instance."""
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
        """Init."""
        """Initialize the class instance."""
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
        result: list[PatternMatch] = []
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
        """Init."""
        """Initialize the class instance."""
        self.registry = PatternRegistry()
        self.matcher = PatternMatcher(self.registry)

    def analyze_function(
        self,
        code: object,
        env: TypeEnvironment | None = None,
    ) -> FunctionPatternInfo:
        """Analyze patterns in a function."""
        instructions = _cached_get_instructions(code)
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
