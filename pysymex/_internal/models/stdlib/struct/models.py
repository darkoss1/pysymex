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

"""Models for the struct standard-library module."""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult
from pysymex._internal.models.stdlib.coercion import const_bytes, const_string

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class StructCalcsizeModel(FunctionModel):
    """Model for struct.calcsize()."""

    name = "calcsize"
    qualname = "struct.calcsize"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        fmt = const_string(args[0]) if args else None
        if fmt is not None:
            try:
                return ModelResult(value=SymbolicValue.from_const(struct.calcsize(fmt)))
            except struct.error:
                pass
        value, constraint = SymbolicValue.symbolic_int(f"struct_calcsize_{state.pc}")
        return ModelResult(value=value, constraints=[constraint, value.z3_int >= 0])


class StructPackModel(FunctionModel):
    """Model for struct.pack()."""

    name = "pack"
    qualname = "struct.pack"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        fmt = const_string(args[0]) if args else None
        if fmt is not None:
            values = [_pack_arg_value(item) for item in args[1:]]
            try:
                return ModelResult(value=SymbolicBytes.concrete(struct.pack(fmt, *values)))
            except struct.error:
                pass
        return ModelResult(value=SymbolicBytes.symbolic(f"struct_pack_{state.pc}"))


class StructUnpackModel(FunctionModel):
    """Model for struct.unpack()."""

    name = "unpack"
    qualname = "struct.unpack"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        fmt = const_string(args[0]) if args else None
        data = const_bytes(args[1]) if len(args) > 1 else None
        if fmt is not None and data is not None:
            try:
                return ModelResult(
                    value=tuple(
                        SymbolicValue.from_const(item) for item in struct.unpack(fmt, data)
                    ),
                )
            except struct.error:
                pass
        value, constraint = SymbolicList.symbolic(f"struct_unpack_{state.pc}")
        return ModelResult(value=value, constraints=[constraint])


def _pack_arg_value(value: object) -> object:
    if isinstance(value, SymbolicValue):
        return value.value
    return value


struct_models: list[FunctionModel] = [
    StructPackModel(),
    StructUnpackModel(),
    StructCalcsizeModel(),
]
