"""Cross-function analysis — pure data types (enums + dataclasses)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Flag, auto

from ..type_inference import PyType, TypeEnvironment

__all__ = [
    "CallContext",
    "CallGraphNode",
    "CallSiteInfo",
    "ContextSensitiveSummary",
    "Effect",
    "EffectSummary",
]


class Effect(Flag):
    """Side effects that a function may have."""

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
    """Summary of effects for a function."""

    effects: Effect = Effect.NONE
    reads_globals: frozenset[str] = frozenset()
    reads_attributes: frozenset[str] = frozenset()
    writes_globals: frozenset[str] = frozenset()
    writes_attributes: frozenset[str] = frozenset()
    may_raise: frozenset[str] = frozenset()
    allocates: frozenset[str] = frozenset()

    @property
    def is_pure(self) -> bool:
        """Check if function is pure (no side effects)."""
        return self.effects == Effect.NONE

    @property
    def is_read_only(self) -> bool:
        """Check if function only reads."""
        return not (self.effects & Effect.WRITE_ANY)

    def merge_with(self, other: EffectSummary) -> EffectSummary:
        """Merge two effect summaries."""
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
    """Information about a call site."""

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
    """Node in the call graph representing a function."""

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
    """
    Context for context-sensitive analysis.
    Uses call-string approach: track the last k call sites.
    """

    call_string: tuple[tuple[str, int], ...] = ()

    def extend(self, caller: str, pc: int, k: int = 2) -> CallContext:
        """Extend context with a new call site."""
        new_string = self.call_string + ((caller, pc),)
        if len(new_string) > k:
            new_string = new_string[-k:]
        return CallContext(new_string)

    def __str__(self) -> str:
        """Str."""
        """Return a human-readable string representation."""
        if not self.call_string:
            return "<entry>"
        return " -> ".join(f"{caller }@{pc }" for caller, pc in self.call_string)


@dataclass
class ContextSensitiveSummary:
    """Summary for a function under a specific context."""

    context: CallContext
    function: str
    type_env: TypeEnvironment | None = None
    effect_summary: EffectSummary | None = None
    param_types: dict[str, PyType] = field(default_factory=dict[str, PyType])
    return_type: PyType | None = None
