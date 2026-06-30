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

"""Models for the uuid standard-library module."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult
from pysymex._internal.models.stdlib.coercion import const_int, const_string, symbolic_object

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class Uuid4Model(FunctionModel):
    """Model for uuid.uuid4()."""

    name = "uuid4"
    qualname = "uuid.uuid4"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del args, kwargs
        value, constraint = SymbolicString.symbolic(f"uuid4_{state.pc}")
        return ModelResult(value=value, constraints=[constraint, value.z3_len == 36])


class UuidConstructorModel(FunctionModel):
    """Model for uuid.UUID()."""

    name = "UUID"
    qualname = "uuid.UUID"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        hex_value = const_string(args[0]) if args else None
        if hex_value is not None:
            try:
                parsed = uuid.UUID(hex_value)
                value, constraint = symbolic_object(f"uuid_{state.pc}", "uuid.UUID")
                value.hex = parsed.hex
                return ModelResult(value=value, constraints=[constraint])
            except (AttributeError, TypeError, ValueError):
                pass
        int_value = kwargs.get("int")
        concrete_int = const_int(int_value) if int_value is not None else None
        if concrete_int is not None:
            try:
                return ModelResult(value=SymbolicValue.from_const(uuid.UUID(int=concrete_int)))
            except (AttributeError, TypeError, ValueError):
                pass
        value, constraint = symbolic_object(f"uuid_{state.pc}", "uuid.UUID")
        return ModelResult(value=value, constraints=[constraint])


uuid_models: list[FunctionModel] = [Uuid4Model(), UuidConstructorModel()]
