# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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
        return f"Def({self.var_name}@{self.pc})"


@dataclass(frozen=True)
class Use:
    """Represents a variable use."""

    var_name: str
    block_id: int
    pc: int
    line: int | None = None

    def __repr__(self) -> str:
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
        return NullInfo(states=dict(self.states))

    def get_state(self, var_name: str) -> NullState:
        return self.states.get(var_name, NullState.UNKNOWN)

    def set_state(self, var_name: str, state: NullState) -> None:
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

            elif s1 == NullState.UNKNOWN or s2 == NullState.UNKNOWN:
                result.states[var] = NullState.UNKNOWN
            else:
                result.states[var] = NullState.MAYBE_NULL
        return result

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NullInfo):
            return False
        return self.states == other.states

    def __hash__(self) -> int:
        """Return the hash value of the object."""
        return hash(tuple(sorted(self.states.items())))
