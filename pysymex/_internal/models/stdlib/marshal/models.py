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

"""Models for the marshal standard-library module."""

from __future__ import annotations

import marshal
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult
from pysymex._internal.models.stdlib.coercion import const_bytes

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

MarshalValue = (
    None
    | bool
    | int
    | float
    | str
    | bytes
    | list["MarshalValue"]
    | tuple["MarshalValue", ...]
    | dict[str, "MarshalValue"]
)


class _NoMarshalValue:
    pass


_NO_MARSHAL_VALUE = _NoMarshalValue()


class MarshalDumpsModel(FunctionModel):
    """Model for marshal.dumps()."""

    name = "dumps"
    qualname = "marshal.dumps"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        value = _marshal_value(args[0]) if args else _NO_MARSHAL_VALUE
        if not isinstance(value, _NoMarshalValue):
            try:
                return ModelResult(value=SymbolicBytes.concrete(marshal.dumps(value)))
            except (TypeError, ValueError):
                pass
        return ModelResult(value=SymbolicBytes.symbolic(f"marshal_dumps_{state.pc}"))


class MarshalLoadsModel(FunctionModel):
    """Model for marshal.loads()."""

    name = "loads"
    qualname = "marshal.loads"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        data = const_bytes(args[0]) if args else None
        if data is not None:
            try:
                return ModelResult(value=SymbolicValue.from_const(marshal.loads(data)))
            except (EOFError, TypeError, ValueError):
                pass
        value, constraint = SymbolicValue.symbolic(f"marshal_loads_{state.pc}")
        return ModelResult(value=value, constraints=[constraint])


def _marshal_value(value: object) -> MarshalValue | _NoMarshalValue:
    if isinstance(value, SymbolicValue):
        value = value.value
    if value is None or isinstance(value, (bool, int, float, str, bytes)):
        return value
    if isinstance(value, list):
        return _marshal_sequence(cast("list[object]", value))
    if isinstance(value, tuple):
        tuple_value = cast("tuple[object, ...]", value)
        items = _marshal_sequence(list(tuple_value))
        if isinstance(items, _NoMarshalValue):
            return _NO_MARSHAL_VALUE
        return tuple(items)
    if isinstance(value, dict):
        values: dict[str, MarshalValue] = {}
        dict_value = cast("dict[object, object]", value)
        for raw_key, raw_value in dict_value.items():
            if not isinstance(raw_key, str):
                return _NO_MARSHAL_VALUE
            converted = _marshal_value(raw_value)
            if isinstance(converted, _NoMarshalValue):
                return _NO_MARSHAL_VALUE
            values[raw_key] = converted
        return values
    return _NO_MARSHAL_VALUE


def _marshal_sequence(values: list[object]) -> list[MarshalValue] | _NoMarshalValue:
    items: list[MarshalValue] = []
    for item in values:
        converted = _marshal_value(item)
        if isinstance(converted, _NoMarshalValue):
            return _NO_MARSHAL_VALUE
        items.append(converted)
    return items


marshal_models: list[FunctionModel] = [MarshalDumpsModel(), MarshalLoadsModel()]
