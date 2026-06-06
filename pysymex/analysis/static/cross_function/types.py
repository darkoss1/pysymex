# pysymex: python symbolic execution & formal verification
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

"""Cross-function analysis — pure data types (enums + dataclasses)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Flag, auto

from pysymex.analysis.static.types import PyType, TypeEnvironment


class Effect(Flag):
    """Bitflag of side effects a function may perform.

    Composite aliases (``READ_ANY``, ``WRITE_ANY``, ``IO``, ``IMPURE``) are
    provided for common queries.  ``PURE`` is synonymous with ``NONE``.
    """

    NONE = 0
    READ_LOCAL = auto()
    WRITE_LOCAL = auto()
    READ_GLOBAL = auto()
    WRITE_GLOBAL = auto()
    READ_HEAP = auto()
    WRITE_HEAP = auto()
    ALLOCATE = auto()
    READ_FILE = auto()
    WRITE_FILE = auto()
    READ_NETWORK = auto()
    WRITE_NETWORK = auto()
    READ_STDIN = auto()
    WRITE_STDOUT = auto()
    RAISE = auto()
    EXIT = auto()
    FORK = auto()
    PURE = NONE
    READ_ANY = READ_LOCAL | READ_GLOBAL | READ_HEAP
    WRITE_ANY = WRITE_LOCAL | WRITE_GLOBAL | WRITE_HEAP
    IO = READ_FILE | WRITE_FILE | READ_NETWORK | WRITE_NETWORK
    IMPURE = READ_ANY | WRITE_ANY | IO | RAISE


@dataclass(frozen=True)
class EffectSummary:
    """Immutable summary of a function's read/write/IO/raise effects.

    Tracks which globals, attributes, and exception types are involved.
    """

    effects: Effect = Effect.NONE
    reads_globals: frozenset[str] = frozenset()
    reads_attributes: frozenset[str] = frozenset()
    writes_globals: frozenset[str] = frozenset()
    writes_attributes: frozenset[str] = frozenset()
    may_raise: frozenset[str] = frozenset()
    allocates: frozenset[str] = frozenset()

    @property
    def is_pure(self) -> bool:
        """Return ``True`` if no side-effect flags are set."""
        return self.effects == Effect.NONE

    @property
    def is_read_only(self) -> bool:
        """Return ``True`` if no write-class flags are set."""
        return not (self.effects & Effect.WRITE_ANY)

    def merge_with(self, other: EffectSummary) -> EffectSummary:
        """Return a new summary with the union of both summaries' effects."""
        return EffectSummary(
            effects=self.effects | other.effects,
            reads_globals=self.reads_globals | other.reads_globals,
            reads_attributes=self.reads_attributes | other.reads_attributes,
            writes_globals=self.writes_globals | other.writes_globals,
            writes_attributes=self.writes_attributes | other.writes_attributes,
            may_raise=self.may_raise | other.may_raise,
            allocates=self.allocates | other.allocates,
        )


@dataclass
class CallSiteInfo:
    """Mutable record of a single call site in bytecode.

    Tracks caller/callee names, source line, bytecode offset, argument
    shape, and whether the call is a method, static, super, or dynamic
    dispatch.  ``possible_callees`` holds resolved targets when the
    callee is not statically known.
    """

    caller: str
    callee: str
    line: int
    pc: int
    arg_count: int = 0
    has_kwargs: bool = False
    has_varargs: bool = False
    is_method_call: bool = False
    is_static: bool = False
    is_super_call: bool = False
    is_dynamic: bool = False
    possible_callees: set[str] = field(default_factory=set[str])


@dataclass
class CallGraphNode:
    """Mutable node in the call graph representing a single function.

    Edges are stored as a list of :class:`CallSiteInfo` objects (callees)
    and a set of caller names.  Optional type environment and effect
    summary are attached by later analysis passes.
    """

    name: str
    qualified_name: str
    callees: list[CallSiteInfo] = field(default_factory=list[CallSiteInfo])
    callers: set[str] = field(default_factory=set[str])
    is_recursive: bool = False
    is_entry_point: bool = False
    type_env: TypeEnvironment | None = None
    effect_summary: EffectSummary | None = None


@dataclass(frozen=True)
class CallContext:
    """Immutable call-string context for context-sensitive analysis.

    Stores the last *k* ``(caller, pc)`` pairs on the call chain.
    A longer chain gives more precision but increases state space.
    """

    call_string: tuple[tuple[str, int], ...] = ()

    def extend(self, caller: str, pc: int, k: int = 2) -> CallContext:
        """Return a new context appending *(caller, pc)*, trimmed to length *k*.

        Args:
            caller: Qualified name of the calling function.
            pc: Bytecode offset of the call instruction.
            k: Maximum call-string length.  Defaults to 2.
        """
        new_string = (*self.call_string, (caller, pc))
        if len(new_string) > k:
            new_string = new_string[-k:]
        return CallContext(new_string)

    def __str__(self) -> str:
        """Return a human-readable string representation."""
        if not self.call_string:
            return "<entry>"
        return " -> ".join(f"{caller}@{pc}" for caller, pc in self.call_string)


@dataclass
class ContextSensitiveSummary:
    """Mutable analysis summary for a function under a specific :class:`CallContext`.

    Holds per-context type environment, effect summary, parameter types,
    and inferred return type.
    """

    context: CallContext
    function: str
    type_env: TypeEnvironment | None = None
    effect_summary: EffectSummary | None = None
    param_types: dict[str, PyType] = field(default_factory=dict[str, PyType])
    return_type: PyType | None = None
