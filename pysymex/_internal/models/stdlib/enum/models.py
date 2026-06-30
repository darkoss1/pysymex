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

"""enum stdlib function models."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class EnumModel(FunctionModel):
    """Model for enum.Enum class construction."""

    name = "Enum"
    qualname = "enum.Enum"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic_int(f"enum_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class IntEnumModel(FunctionModel):
    """Model for enum.IntEnum class construction."""

    name = "IntEnum"
    qualname = "enum.IntEnum"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic_int(f"intenum_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class EnumAutoModel(FunctionModel):
    """Model for enum.auto() to generate enum values."""

    name = "auto"
    qualname = "enum.auto"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic_int(f"enum_auto_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.z3_int >= 1])


class EnumValueModel(FunctionModel):
    """Model for accessing Enum.value property."""

    name = "value"
    qualname = "enum.Enum.value"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"enum_value_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class EnumNameModel(FunctionModel):
    """Model for accessing Enum.name property."""

    name = "name"
    qualname = "enum.Enum.name"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"enum_name_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


enum_models = [
    EnumModel(),
    IntEnumModel(),
    EnumAutoModel(),
    EnumValueModel(),
    EnumNameModel(),
]
