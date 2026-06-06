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

"""Symbolic FunctionModel handlers for the ``dataclasses`` module.

Runtime-mimicking dataclass helper functions live under
``pysymex.models.stdlib.dataclasses``. This module owns only symbolic
``FunctionModel`` instances registered with the stdlib model registry.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.core.identity.addressing import next_address
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins import FunctionModel, ModelResult

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


class DataclassModel(FunctionModel):
    """Model for @dataclass decorator."""

    name = "dataclass"
    qualname = "dataclasses.dataclass"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if args:
            return ModelResult(value=args[0])
        result, constraint = SymbolicValue.symbolic(f"dataclass_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class DataclassFieldModel(FunctionModel):
    """Model for dataclasses.field() function."""

    name = "field"
    qualname = "dataclasses.field"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        default = kwargs.get("default")
        default_factory = kwargs.get("default_factory")
        if default is not None:
            return ModelResult(value=default)
        if default_factory is not None:
            result, constraint = SymbolicValue.symbolic(f"field_factory_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        result, constraint = SymbolicValue.symbolic(f"field_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class AsDataclassModel(FunctionModel):
    """Model for dataclasses.asdict() function."""

    name = "asdict"
    qualname = "dataclasses.asdict"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicDict.symbolic(f"asdict_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class AstupleModel(FunctionModel):
    """Model for dataclasses.astuple() function."""

    name = "astuple"
    qualname = "dataclasses.astuple"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"astuple_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class FieldsModel(FunctionModel):
    """Model for dataclasses.fields() function."""

    name = "fields"
    qualname = "dataclasses.fields"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"fields_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 0])


class ReplaceModel(FunctionModel):
    """Model for dataclasses.replace() function."""

    name = "replace"
    qualname = "dataclasses.replace"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if args:
            addr = next_address()
            result, constraint = SymbolicObject.symbolic(f"replaced_{state.pc}", addr)
            obj_state = {}
            if kwargs:
                for k, v in kwargs.items():
                    obj_state[k] = v
            state.memory[addr] = obj_state
            return ModelResult(value=result, constraints=[constraint])
        result, constraint = SymbolicValue.symbolic(f"replace_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


dataclasses_models = [
    DataclassModel(),
    DataclassFieldModel(),
    AsDataclassModel(),
    AstupleModel(),
    FieldsModel(),
    ReplaceModel(),
]


__all__ = [
    "AsDataclassModel",
    "AstupleModel",
    "DataclassFieldModel",
    "DataclassModel",
    "FieldsModel",
    "ReplaceModel",
    "dataclasses_models",
]
