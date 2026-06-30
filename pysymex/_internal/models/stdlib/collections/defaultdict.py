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

"""defaultdict model for collections."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.identity.addressing import next_address
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class DefaultDictConstructorModel(FunctionModel):
    """Model ``defaultdict(int)`` zero-valued subscript reads."""

    name = "defaultdict"
    qualname = "collections.defaultdict"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args or args[0] is not int:
            result, constraint = SymbolicValue.symbolic(f"defaultdict_unknown_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])

        storage = SymbolicDict.empty(f"defaultdict_{state.pc}")
        storage.enable_default_factory()
        address = next_address()
        handle = SymbolicObject(
            f"defaultdict_{address}",
            address,
            ConstraintValues.int(address),
            {address},
        )
        state.store_heap(address, storage)
        return ModelResult(value=handle)


class DefaultDictModel:
    """Model for collections.defaultdict.

    A dict subclass that calls a factory function to supply missing values.
    Key property: __getitem__ never raises KeyError.
    """

    @staticmethod
    def model_init(
        state: VMState,
        default_factory: object = None,
    ) -> SymbolicDict:
        """Model defaultdict() initialization."""
        dd = SymbolicDict.empty("defaultdict")
        dd.enable_default_factory()
        return dd

    @staticmethod
    def model_getitem(
        dd: SymbolicDict,
        key: SymbolicValue,
    ) -> SymbolicValue:
        """Model defaultdict[key]."""
        from pysymex._internal.core.types.scalars.values import SymbolicValue

        result, _ = SymbolicValue.symbolic(f"defaultdict_value_{key}")
        return result

    @staticmethod
    def model_missing(
        dd: SymbolicDict,
        key: SymbolicValue,
    ) -> SymbolicValue:
        """Model defaultdict.__missing__(key)."""
        from pysymex._internal.core.types.scalars.values import SymbolicValue

        result, _ = SymbolicValue.symbolic(f"defaultdict_default_{key}")
        return result


DEFAULTDICT_MODELS: list[FunctionModel] = [DefaultDictConstructorModel()]
