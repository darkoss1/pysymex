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

"""Symbolic object type records."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto

import z3

from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue


class MethodType(Enum):
    """Types of class methods."""

    INSTANCE = auto()
    CLASS = auto()
    STATIC = auto()
    PROPERTY = auto()
    ABSTRACT = auto()
    MAGIC = auto()


@dataclass(frozen=True, slots=True)
class SymbolicAttribute:
    """A symbolic class/instance attribute."""

    name: str
    value: object
    is_class_attr: bool = False
    is_readonly: bool = False
    type_hint: str | None = None

    def with_value(self, new_value: object) -> SymbolicAttribute:
        """Create copy with new value."""
        return SymbolicAttribute(
            name=self.name,
            value=new_value,
            is_class_attr=self.is_class_attr,
            is_readonly=self.is_readonly,
            type_hint=self.type_hint,
        )


@dataclass
class SymbolicMethod:
    """A symbolic method definition."""

    name: str
    func: object = None
    method_type: MethodType = MethodType.INSTANCE
    parameters: list[str] = field(default_factory=list[str])
    return_type: str | None = None
    is_abstract: bool = False
    preconditions: list[z3.BoolRef] = field(default_factory=list[z3.BoolRef])
    postconditions: list[z3.BoolRef] = field(default_factory=list[z3.BoolRef])
    modifies: set[str] = field(default_factory=set[str])
    bound_to: object | None = None

    @property
    def is_bound(self) -> bool:
        """Return whether this method carries an implicit first argument."""
        return self.bound_to is not None

    def bind_to_instance(self, instance: object) -> SymbolicMethod:
        """Bind an instance method to a modeled object value."""
        if self.method_type == MethodType.STATIC:
            return self
        return self._bound_copy(instance)

    def bind_to_class(self, cls: object) -> SymbolicMethod:
        """Bind a class method to its modeled class."""
        return self._bound_copy(cls)

    def _bound_copy(self, target: object) -> SymbolicMethod:
        return SymbolicMethod(
            name=self.name,
            func=self.func,
            method_type=self.method_type,
            parameters=self.parameters,
            return_type=self.return_type,
            is_abstract=self.is_abstract,
            preconditions=self.preconditions,
            postconditions=self.postconditions,
            modifies=self.modifies,
            bound_to=target,
        )

    def get_call_args(
        self,
        args: tuple[object, ...],
        kwargs: dict[str, object],
    ) -> tuple[tuple[object, ...], dict[str, object]]:
        """Insert the bound receiver exactly once for modeled dispatch."""
        if self.method_type == MethodType.STATIC or self.bound_to is None:
            return args, kwargs
        if args and args[0] is self.bound_to:
            return args, kwargs
        return (self.bound_to, *args), kwargs


@dataclass
class InitParameter:
    """Parameter information for __init__."""

    name: str
    type_hint: str | None = None
    default: object = None
    default_factory: Callable[[], object] | None = None
    has_default: bool = False
    is_self: bool = False

    def to_symbolic(self, pc: int) -> object:
        """Create a symbolic value for this parameter."""
        if self.is_self:
            return None
        type_map = {
            "int": lambda: SymbolicValue.symbolic_int(f"init_{self.name}_{pc}")[0],
            "str": lambda: SymbolicString.symbolic(f"init_{self.name}_{pc}")[0],
            "float": lambda: SymbolicValue.symbolic_float(f"init_{self.name}_{pc}")[0],
            "bool": lambda: SymbolicValue.symbolic_bool(f"init_{self.name}_{pc}")[0],
            "list": lambda: SymbolicList.symbolic(f"init_{self.name}_{pc}")[0],
            "dict": lambda: SymbolicDict.symbolic(f"init_{self.name}_{pc}")[0],
        }
        if self.type_hint in type_map:
            return type_map[self.type_hint]()
        if self.has_default:
            return self.default
        return SymbolicValue.symbolic(f"init_{self.name}_{pc}")[0]


__all__ = ["InitParameter", "MethodType", "SymbolicAttribute", "SymbolicMethod"]
