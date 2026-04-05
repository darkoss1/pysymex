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

"""Shared type aliases, TypeVars, and Protocol definitions for pysymex.

This module is the single source of truth for cross-cutting type
abstractions used by two or more sub-packages.  Import from here
rather than re-declaring ``TypeVar`` / ``Protocol`` locally.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import (
    TYPE_CHECKING,
    Protocol,
    Self,
    TypeAlias,
    TypeGuard,
    TypeVar,
    runtime_checkable,
)

import z3

T = TypeVar("T")
T_co = TypeVar("T_co", covariant=True)
K = TypeVar("K")
V = TypeVar("V")


from pysymex.core.types import AnySymbolic

if TYPE_CHECKING:
    from pysymex.core.floats import SymbolicFloat
    from pysymex.core.solver import SolverResult
    from pysymex.core.types_containers import SymbolicIterator

    _SymbolicFloatType = SymbolicFloat
    _SymbolicIteratorType = SymbolicIterator
else:
    _SymbolicFloatType = object
    _SymbolicIteratorType = object

StackValue: TypeAlias = (
    AnySymbolic
    | int
    | bool
    | str
    | float
    | bytes
    | None
    | type
    | Callable[..., object]
    | list["StackValue"]
    | dict[str, "StackValue"]
    | tuple["StackValue", ...]
    | _SymbolicFloatType
    | _SymbolicIteratorType
)


SideEffects: TypeAlias = dict[str, StackValue]


ConstraintList: TypeAlias = Sequence[z3.ExprRef | z3.BoolRef]


JsonValue: TypeAlias = int | str | bool | float | None | list["JsonValue"] | dict[str, "JsonValue"]
JsonDict: TypeAlias = dict[str, JsonValue]


UserCallable: TypeAlias = Callable[..., object]


@runtime_checkable
class SummaryProtocol(Protocol):
    """Protocol for function summaries being built."""

    parameters: list[object]
    preconditions: list[object]
    postconditions: list[object]
    modified: list[object]
    reads: list[object]
    calls: list[object]
    may_raise: list[object]


@runtime_checkable
class SummaryBuilderProtocol(Protocol):
    """Protocol for summary builders in state management."""

    summary: SummaryProtocol
    _initial_args: list[object]


Counterexample: TypeAlias = Mapping[str, int | str | bool | float | None]


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


@runtime_checkable
class SolverProtocol(Protocol):
    """Abstract solver interface satisfied by IncrementalSolver, ShadowSolver, etc."""

    def check(self, *assumptions: z3.BoolRef) -> SolverResult | z3.CheckSatResult:
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

    def is_sat(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> bool:
        """Convenience SAT check for a standalone constraint list."""
        ...

    def get_stats(self) -> dict[str, object]:
        """Return implementation-defined solver statistics."""
        ...

    def constraint_optimizer(self) -> object:
        """Expose the associated constraint optimizer instance."""
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


def is_symbolic_value(obj: object) -> TypeGuard[SymbolicTypeProtocol]:
    """TypeGuard narrowing for any symbolic type (SymbolicValue from core.types)."""
    from pysymex.core.types import SymbolicValue

    return isinstance(obj, SymbolicValue)


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
class VerificationResultProtocol(Protocol):
    """Protocol for verification results."""

    can_crash: bool
    proven_safe: bool
    z3_status: str
    verification_time_ms: float
    crash: object | None


@runtime_checkable
class TaintTrackerProtocol(Protocol):
    """Protocol for taint tracking in execution state."""

    def fork(self) -> TaintTrackerProtocol:
        """Create an independent copy for state forking."""
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


def is_symbolic_string(obj: object) -> TypeGuard[SymbolicStringProtocol]:
    """TypeGuard narrowing for symbolic string types."""
    from pysymex.core.types_containers import SymbolicString

    return isinstance(obj, SymbolicString)


def is_symbolic_container(obj: object) -> TypeGuard[SymbolicContainerProtocol]:
    """TypeGuard narrowing for symbolic container types (list, dict, set, tuple)."""
    from pysymex.core.types_containers import (
        SymbolicDict,
        SymbolicList,
        SymbolicObject,
    )

    return isinstance(obj, (SymbolicList, SymbolicDict, SymbolicObject))


@runtime_checkable
class TaintableProtocol(Protocol):
    """Protocol for values that can have taint labels applied."""

    def with_taint(self, label: str | set[str] | frozenset[str]) -> Self:
        """Return a copy with the given taint label(s) applied."""
        ...


def is_taintable(obj: object) -> TypeGuard[TaintableProtocol]:
    """TypeGuard narrowing for types that support taint propagation.

    Returns True if the object has a `with_taint` method that can
    be used to propagate taint labels during symbolic execution.
    """
    return hasattr(obj, "with_taint") and callable(getattr(obj, "with_taint", None))


__all__ = [
    "AnySymbolic",
    "ConstraintList",
    "Counterexample",
    "DetectorProtocol",
    "JsonDict",
    "K",
    "SideEffects",
    "SolverProtocol",
    "StackValue",
    "StateViewProtocol",
    "SymbolicContainerProtocol",
    "SymbolicStringProtocol",
    "SymbolicTypeProtocol",
    "T",
    "T_co",
    "TaintableProtocol",
    "UserCallable",
    "V",
    "is_symbolic_container",
    "is_symbolic_string",
    "is_symbolic_value",
    "is_taintable",
]
