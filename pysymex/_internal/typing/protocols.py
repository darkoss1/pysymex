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

"""Shared type aliases and Protocol definitions for pysymex.

This module is the single source of truth for cross-cutting type
abstractions used by two or more sub-packages.  Import from here
rather than re-declaring ``Protocol`` types locally.
"""

from __future__ import annotations

import types
from collections.abc import Callable, Iterable
from typing import (
    TYPE_CHECKING,
    Protocol,
    runtime_checkable,
)

import z3

if TYPE_CHECKING:
    from pysymex._internal.core.exceptions.objects import SymbolicException
    from pysymex._internal.core.solver.engine.results import SolverResult
    from pysymex._internal.core.types.containers.callable_iterators import CallableSentinelIterator
    from pysymex._internal.core.types.containers.generators import ModeledGenerator
    from pysymex._internal.core.types.containers.iterators import SymbolicIterator
    from pysymex._internal.core.types.numeric.float import SymbolicFloat

    _SymbolicFloatType = SymbolicFloat
    _CallableSentinelIteratorType = CallableSentinelIterator
    _ModeledGeneratorType = ModeledGenerator
    _SymbolicIteratorType = SymbolicIterator
    _SymbolicExceptionType = SymbolicException
else:
    _SymbolicFloatType = object
    _CallableSentinelIteratorType = object
    _ModeledGeneratorType = object
    _SymbolicIteratorType = object
    _SymbolicExceptionType = object


@runtime_checkable
class SymbolicTypeProtocol(Protocol):
    """Read-only view of any symbolic type (SymbolicValue, SymbolicNone, …)."""

    @property
    def name(self) -> str:
        """The symbolic name or identifier of this type."""
        ...

    def to_z3(self) -> z3.ExprRef:
        """Convert the symbolic value to its underlying Z3 expression."""
        ...

    def could_be_truthy(self) -> z3.BoolRef:
        """Check if there exists a model where this value is truthy."""
        ...

    def could_be_falsy(self) -> z3.BoolRef:
        """Check if there exists a model where this value is falsy."""
        ...


StackValue = (
    SymbolicTypeProtocol
    | z3.ExprRef
    | int
    | bool
    | str
    | float
    | bytes
    | None
    | type
    | types.CodeType
    | Callable[..., object]
    | list["StackValue"]
    | dict[str, "StackValue"]
    | tuple["StackValue", ...]
    | _SymbolicFloatType
    | _CallableSentinelIteratorType
    | _ModeledGeneratorType
    | _SymbolicIteratorType
    | _SymbolicExceptionType
)


@runtime_checkable
class SolverProtocol(Protocol):
    """Abstract solver interface satisfied by IncrementalSolver-compatible implementations."""

    def check(
        self,
        *assumptions: z3.BoolRef,
        need_model: bool = True,
    ) -> SolverResult | z3.CheckSatResult:
        """Check satisfiability of current constraints with optional assumptions."""
        ...

    def push(self) -> None:
        """Push a new constraint scope."""
        ...

    def pop(self) -> None:
        """Pop the current constraint scope."""
        ...

    def add(self, *constraints: z3.BoolRef) -> None:
        """Add one or more constraints to the current scope."""
        ...

    def reset(self) -> None:
        """Reset internal solver state and caches."""
        ...

    def path_may_be_feasible(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> bool:
        """Return whether constraints are not established UNSAT (SAT or UNKNOWN)."""
        ...

    def check_sat_result(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> SolverResult:
        """Return a standalone constraint check without collapsing ``unknown``."""
        ...

    def get_model(self, constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
        """Return a satisfying model for a standalone constraint list."""
        ...

    def check_sat_cached(
        self,
        constraints: list[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> SolverResult:
        """Return structured SAT evidence for constraints, including a model when SAT."""
        ...

    def get_stats(self) -> dict[str, object]:
        """Return implementation-defined solver statistics."""
        ...

    def constraint_optimizer(self) -> object:
        """Expose the associated constraint optimizer instance."""
        ...

    def set_deadline(self, deadline_time: float | None) -> None:
        """Set an absolute solver deadline as a ``time.perf_counter()`` value."""
        ...


@runtime_checkable
class DetectorProtocol(Protocol):
    """Interface every bug detector must implement."""

    @property
    def name(self) -> str:
        """The human-readable name of the detector."""
        ...

    def check(self, state: StateViewProtocol, instruction: object) -> object | None:
        """Perform a bug detection check at the current execution point."""
        ...


@runtime_checkable
class StateViewProtocol(Protocol):
    """Read-only view of VMState for analysis passes that must not mutate."""

    @property
    def pc(self) -> int:
        """The current program counter (instruction offset)."""
        ...

    @property
    def local_vars(self) -> object:
        """A view of the local variables in the current frame."""
        ...

    @property
    def stack(self) -> list[StackValue]:
        """A view of the operand stack."""
        ...

    @property
    def path_constraints(self) -> list[z3.BoolRef]:
        """The set of Z3 constraints defining the current execution path."""
        ...


@runtime_checkable
class SymbolicStringProtocol(Protocol):
    """Protocol for symbolic string values."""

    @property
    def name(self) -> str:
        """The symbolic name of the string."""
        ...

    def to_z3(self) -> z3.ExprRef:
        """The Z3 string expression."""
        ...

    def is_truthy(self) -> z3.BoolRef:
        """Z3 check for non-emptiness."""
        ...

    def is_falsy(self) -> z3.BoolRef:
        """Z3 check for emptiness."""
        ...

    def length(self) -> object:
        """The symbolic length of the string."""
        ...


@runtime_checkable
class SymbolicContainerProtocol(Protocol):
    """Protocol for symbolic container values (List, Dict, Set, Tuple)."""

    @property
    def name(self) -> str:
        """The symbolic name of the container."""
        ...

    def to_z3(self) -> z3.ExprRef:
        """The underlying Z3 representation."""
        ...

    def is_truthy(self) -> z3.BoolRef:
        """Check if the container is non-empty."""
        ...

    def is_falsy(self) -> z3.BoolRef:
        """Check if the container is empty."""
        ...

    def symbolic_eq(self, other: object) -> z3.BoolRef:
        """Symbolic equality check between two containers."""
        ...
