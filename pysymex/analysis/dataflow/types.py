"""
Data Flow Analysis Types for pysymex.

Contains dataclasses, enums, and type-only definitions used by the
data flow analysis framework.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    TypeVar,
)

__all__ = [
    "DefUseChain",
    "Definition",
    "Expression",
    "NullInfo",
    "NullState",
    "T",
    "Use",
]

T = TypeVar("T")


@dataclass(frozen=True)
class Definition:
    """Represents a variable definition."""

    var_name: str
    block_id: int
    pc: int
    line: int | None = None

    def __repr__(self) -> str:
        """Repr."""
        """Return a formal string representation."""
        return f"Def({self.var_name}@{self.pc})"


@dataclass(frozen=True)
class Use:
    """Represents a variable use."""

    var_name: str
    block_id: int
    pc: int
    line: int | None = None

    def __repr__(self) -> str:
        """Repr."""
        """Return a formal string representation."""
        return f"Use({self.var_name}@{self.pc})"


@dataclass
class DefUseChain:
    """
    Def-use chain linking definitions to their uses.

    Used for:
    - Data flow tracking
    - Taint analysis
    - Dead store detection
    """

    definition: Definition
    uses: set[Use] = field(default_factory=set[Use])

    def add_use(self, use: Use) -> None:
        """Add a use of this definition."""
        self.uses.add(use)

    def is_dead(self) -> bool:
        """Check if this definition has no uses."""
        return len(self.uses) == 0


@dataclass(frozen=True)
class Expression:
    """Represents an expression."""

    operator: str
    operands: tuple[str, ...]

    def __repr__(self) -> str:
        """Repr."""
        """Return a formal string representation."""
        if len(self.operands) == 1:
            return f"{self.operator}({self.operands[0]})"
        return f"({self.operands[0]} {self.operator} {self.operands[1]})"


class NullState(Enum):
    """Possible null states for a variable."""

    DEFINITELY_NULL = auto()
    DEFINITELY_NOT_NULL = auto()
    MAYBE_NULL = auto()
    UNKNOWN = auto()


@dataclass
class NullInfo:
    """Null information for variables."""

    states: dict[str, NullState] = field(default_factory=dict[str, NullState])

    def copy(self) -> NullInfo:
        """Copy."""
        return NullInfo(states=dict(self.states))

    def get_state(self, var_name: str) -> NullState:
        """Get state."""
        return self.states.get(var_name, NullState.UNKNOWN)

    def set_state(self, var_name: str, state: NullState) -> None:
        """Set state."""
        self.states[var_name] = state

    def join(self, other: NullInfo) -> NullInfo:
        """Join two null infos."""
        result = NullInfo()
        all_vars = set(self.states.keys()) | set(other.states.keys())
        for var in all_vars:
            s1 = self.get_state(var)
            s2 = other.get_state(var)
            if s1 == s2:
                result.states[var] = s1
            elif s1 == NullState.UNKNOWN:
                result.states[var] = s2
            elif s2 == NullState.UNKNOWN:
                result.states[var] = s1
            else:
                result.states[var] = NullState.MAYBE_NULL
        return result

    def __eq__(self, other: object) -> bool:
        """Eq."""
        """Check for equality with another object."""
        if not isinstance(other, NullInfo):
            return False
        return self.states == other.states

    def __hash__(self) -> int:
        """Hash."""
        """Return the hash value of the object."""
        return hash(tuple(sorted(self.states.items())))
