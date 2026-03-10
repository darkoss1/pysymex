"""Shared type aliases, TypeVars, and Protocol definitions for pysymex.

This module is the single source of truth for cross-cutting type
abstractions used by two or more sub-packages.  Import from here
rather than re-declaring ``TypeVar`` / ``Protocol`` locally.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import (
    Protocol,
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


from pysymex.core.havoc import HavocValue as HavocValue
from pysymex.core.types import AnySymbolic as AnySymbolic

StackValue = AnySymbolic | int | bool | str | float | bytes | None


SideEffects: TypeAlias = dict[str, object]


ConstraintList: TypeAlias = Sequence[z3.ExprRef | z3.BoolRef]


JsonDict: TypeAlias = dict[str, object]


UserCallable: TypeAlias = Callable[..., object]


Counterexample: TypeAlias = Mapping[str, int | str | bool | float | None]


@runtime_checkable
class SymbolicTypeProtocol(Protocol):
    """Read-only view of any symbolic type (SymbolicValue, SymbolicNone, …)."""

    @property
    def name(self) -> str: ...
    def to_z3(self) -> z3.ExprRef: ...
    def could_be_truthy(self) -> z3.BoolRef: ...
    def could_be_falsy(self) -> z3.BoolRef: ...


@runtime_checkable
class SolverProtocol(Protocol):
    """Abstract solver interface satisfied by IncrementalSolver, ShadowSolver, etc."""

    def check(self, *assumptions: z3.BoolRef) -> object: ...
    def push(self) -> None: ...
    def pop(self) -> None: ...
    def add(self, *constraints: z3.BoolRef) -> None: ...


@runtime_checkable
class DetectorProtocol(Protocol):
    """Interface every bug detector must implement."""

    @property
    def name(self) -> str: ...
    def check(self, state: object, instruction: object) -> object | None: ...


@runtime_checkable
class StateViewProtocol(Protocol):
    """Read-only view of VMState for analysis passes that must not mutate."""

    @property
    def pc(self) -> int: ...
    @property
    def local_vars(self) -> object: ...
    @property
    def stack(self) -> list[StackValue]: ...
    @property
    def path_constraints(self) -> list[z3.BoolRef]: ...


def is_symbolic_value(obj: object) -> TypeGuard[SymbolicTypeProtocol]:
    """TypeGuard narrowing for any symbolic type (SymbolicValue from core.types)."""
    from pysymex.core.types import SymbolicValue

    return isinstance(obj, SymbolicValue)


@runtime_checkable
class SymbolicStringProtocol(Protocol):
    """Protocol for symbolic string values."""

    @property
    def name(self) -> str: ...
    def to_z3(self) -> z3.ExprRef: ...
    def is_truthy(self) -> z3.BoolRef: ...
    def is_falsy(self) -> z3.BoolRef: ...
    def length(self) -> object: ...


@runtime_checkable
class SymbolicContainerProtocol(Protocol):
    """Protocol for symbolic container values (List, Dict, Set, Tuple)."""

    @property
    def name(self) -> str: ...
    def to_z3(self) -> z3.ExprRef: ...
    def is_truthy(self) -> z3.BoolRef: ...
    def is_falsy(self) -> z3.BoolRef: ...
    def symbolic_eq(self, other: object) -> z3.BoolRef: ...


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
    "UserCallable",
    "V",
    "is_symbolic_container",
    "is_symbolic_string",
    "is_symbolic_value",
]
