# pysymex: Python Symbolic Execution & Formal Verification
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

"""Type models for Python builtin types.

Contains models for Python type objects (classes) that are not functions:
exception types, type constructors, and other builtin type references.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import z3

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState


def _new_side_effects() -> dict[str, object]:
    """Create an empty side-effects map."""
    return {}


@dataclass(frozen=True, slots=True)
class TypeModelResult:
    """Result of a type model application."""

    value: StackValue
    constraints: Sequence[z3.ExprRef | z3.BoolRef] = field(default_factory=tuple)
    side_effects: dict[str, object] = field(default_factory=_new_side_effects)


class TypeModel(ABC):
    """Base class for type object models.

    Unlike FunctionModel which models callable functions, TypeModel models
    type objects (classes) that can be referenced, used in isinstance(),
    or instantiated.
    """

    name: str = "unknown"
    qualname: str = "unknown"
    python_type: type | None = None

    @abstractmethod
    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> TypeModelResult:
        """
        Apply the type model (e.g., for instantiation or type checking).
        Args:
            args: Positional arguments (for instantiation)
            kwargs: Keyword arguments (for instantiation)
            state: Current VM state
        Returns:
            TypeModelResult with symbolic result and any constraints
        """

    def matches(self, obj: object) -> bool:
        """Check if this model matches a given type object."""
        if self.python_type is not None:
            return obj is self.python_type
        obj_name = getattr(obj, "__name__", None)
        if isinstance(obj_name, str):
            return obj_name == self.name
        return str(obj) == self.name


class BuiltinTypeModel(TypeModel):
    """Model for builtin type objects like int, str, list, etc."""

    def __init__(self, py_type: type) -> None:
        self.name = py_type.__name__
        self.qualname = f"builtins.{py_type.__name__}"
        self.python_type = py_type

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> TypeModelResult:
        """
        Apply the builtin type model.

        When instantiated (e.g., int("42")), the FunctionModel for the
        constructor will be used. When referenced (e.g., isinstance(x, int)),
        return the actual Python type object.
        """
        return TypeModelResult(value=self.python_type)


IntModel = BuiltinTypeModel(int)
StrModel = BuiltinTypeModel(str)
ListModel = BuiltinTypeModel(list)
DictModel = BuiltinTypeModel(dict)
TupleModel = BuiltinTypeModel(tuple)
SetModel = BuiltinTypeModel(set)
BoolModel = BuiltinTypeModel(bool)
ObjectModel = BuiltinTypeModel(object)
TypeTypeModel = BuiltinTypeModel(type)
FloatModel = BuiltinTypeModel(float)
BytesModel = BuiltinTypeModel(bytes)
BytearrayModel = BuiltinTypeModel(bytearray)
FrozensetModel = BuiltinTypeModel(frozenset)
NoneTypeModel = BuiltinTypeModel(type(None))
