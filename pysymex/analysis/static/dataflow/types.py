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

"""Domain types for intra-procedural dataflow analysis.

Defines definitions, uses, def-use chains, expressions, and null-state
lattice models shared by reaching definitions, liveness, and nullness
analysis passes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    TypeVar,
)

T = TypeVar("T")


@dataclass(frozen=True)
class Definition:
    """Immutable record of a single variable definition (store) in bytecode.

    Attributes:
        var_name: Name of the defined variable.
        block_id: CFG basic-block index containing this definition.
        pc: Bytecode offset of the store instruction.
        line: Source line number, if known.
    """

    var_name: str
    block_id: int
    pc: int
    line: int | None = None

    def __repr__(self) -> str:
        """Return a string representation of the Definition.

        Returns:
            A string containing the variable name and PC of the definition.
        """
        return f"Def({self.var_name}@{self.pc})"


@dataclass(frozen=True)
class Use:
    """Immutable record of a single variable use (load) in bytecode.

    Attributes:
        var_name: Name of the used variable.
        block_id: CFG basic-block index containing this use.
        pc: Bytecode offset of the load instruction.
        line: Source line number, if known.
    """

    var_name: str
    block_id: int
    pc: int
    line: int | None = None

    def __repr__(self) -> str:
        """Return a string representation of the Use.

        Returns:
            A string containing the variable name and PC of the use.
        """
        return f"Use({self.var_name}@{self.pc})"


@dataclass
class DefUseChain:
    """Links a single :class:`Definition` to all its :class:`Use` sites.

    Used by reaching-definition analysis and dead-store detection.
    A chain with no uses (``is_dead() == True``) indicates a dead store.
    """

    definition: Definition
    uses: set[Use] = field(default_factory=set[Use])

    def add_use(self, use: Use) -> None:
        """Add a use of this definition."""
        self.uses.add(use)

    def is_dead(self) -> bool:
        """Return ``True`` if this definition has no recorded uses (dead store)."""
        return len(self.uses) == 0


@dataclass(frozen=True)
class Expression:
    """Immutable bytecode-level expression for available-expression analysis.

    Attributes:
        operator: Opcode or operation name.
        operands: Tuple of operand variable names.
    """

    operator: str
    operands: tuple[str, ...]

    def __repr__(self) -> str:
        """Format as ``op(a)`` (unary) or ``(a op b)`` (binary)."""
        if len(self.operands) == 1:
            return f"{self.operator}({self.operands[0]})"
        return f"({self.operands[0]} {self.operator} {self.operands[1]})"


class NullState(Enum):
    """Four-valued lattice for variable nullability.

    ``MAYBE_NULL`` represents the join of ``DEFINITELY_NULL`` and
    ``DEFINITELY_NOT_NULL``.  ``UNKNOWN`` is the top element when
    no information is available.
    """

    DEFINITELY_NULL = auto()
    DEFINITELY_NOT_NULL = auto()
    MAYBE_NULL = auto()
    UNKNOWN = auto()


@dataclass
class NullInfo:
    """Mutable map of variable names to :class:`NullState` values.

    Supports lattice join via :meth:`join` for merging control-flow paths.
    """

    states: dict[str, NullState] = field(default_factory=dict[str, NullState])

    def copy(self) -> NullInfo:
        """Create a shallow copy of this NullInfo instance.

        Returns:
            A new NullInfo instance with a copy of the states dictionary.
        """
        return NullInfo(states=dict(self.states))

    def get_state(self, var_name: str) -> NullState:
        """Retrieve the null state of a variable.

        Args:
            var_name: The name of the variable.

        Returns:
            The NullState of the variable, defaulting to NullState.UNKNOWN if not found.
        """
        return self.states.get(var_name, NullState.UNKNOWN)

    def set_state(self, var_name: str, state: NullState) -> None:
        """Set the null state of a variable.

        Args:
            var_name: The name of the variable.
            state: The NullState to assign.
        """
        self.states[var_name] = state

    def clear_state(self, var_name: str) -> None:
        """Remove a variable's state from the tracked null information.

        Args:
            var_name: The name of the variable.
        """
        self.states.pop(var_name, None)

    def join(self, other: NullInfo) -> NullInfo:
        """Return a new ``NullInfo`` that is the lattice join of ``self`` and *other*.

        Equal states are preserved; otherwise the result is ``MAYBE_NULL``
        (or ``UNKNOWN`` if either input is ``UNKNOWN``).
        """
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
        """Determine if this NullInfo is equal to another object.

        Args:
            other: The object to compare with.

        Returns:
            True if the other object is a NullInfo instance with identical variable states,
            otherwise False.
        """
        if not isinstance(other, NullInfo):
            return False
        return self.states == other.states

    def __hash__(self) -> int:
        """Return the hash value of the object."""
        return hash(tuple(sorted(self.states.items())))
