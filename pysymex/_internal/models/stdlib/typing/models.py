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

"""Models for the typing standard-library module."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult, SideEffects

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class TypingGetOriginModel(FunctionModel):
    """Model for typing.get_origin()."""

    name = "get_origin"
    qualname = "typing.get_origin"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs, state
        if args:
            try:
                from typing import get_origin

                return ModelResult(value=SymbolicValue.from_const(get_origin(args[0])))
            except TypeError:
                pass
        return ModelResult(value=SymbolicValue.from_const(None))


class TypingGetArgsModel(FunctionModel):
    """Model for typing.get_args()."""

    name = "get_args"
    qualname = "typing.get_args"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs, state
        if args:
            try:
                from typing import get_args

                return ModelResult(value=get_args(args[0]))
            except TypeError:
                pass
        return ModelResult(value=())


class TypingCastModel(FunctionModel):
    """Model ``typing.cast`` as its exact runtime identity operation."""

    name = "cast"
    qualname = "typing.cast"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del state
        if kwargs or len(args) != 2:
            return ModelResult.none(
                SideEffects.type_error(self.qualname, "cast() takes a type and a value"),
            )
        return ModelResult(value=args[1])


typing_models: list[FunctionModel] = [
    TypingCastModel(),
    TypingGetOriginModel(),
    TypingGetArgsModel(),
]
