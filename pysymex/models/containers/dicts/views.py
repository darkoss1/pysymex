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

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.core.types.containers.dict_views import SymbolicDictView

from .shared import (
    FunctionModel,
    ModelResult,
    SymbolicDict,
    SymbolicList,
    dict_type_error_result,
    get_symbolic_dict,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

"""Dictionary view and copy symbolic models."""


class DictKeysModel(FunctionModel):
    """Model for dict.keys() - returns view of keys.
    Relationship: len(keys) == len(dict)
    """

    name = "keys"
    qualname = "dict.keys"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return dict_type_error_result(self.name, state)
        d = get_symbolic_dict(args[0], state) if args else None
        if d is not None:
            return ModelResult(value=SymbolicDictView(f"dict_keys_{state.pc}", d, "keys"))
        result, constraint = SymbolicList.symbolic(f"dict_keys_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class DictValuesModel(FunctionModel):
    """Model for dict.values() - returns view of values.
    Relationship: len(values) == len(dict)
    """

    name = "values"
    qualname = "dict.values"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return dict_type_error_result(self.name, state)
        d = get_symbolic_dict(args[0], state) if args else None
        if d is not None:
            return ModelResult(value=SymbolicDictView(f"dict_values_{state.pc}", d, "values"))
        result, constraint = SymbolicList.symbolic(f"dict_values_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class DictItemsModel(FunctionModel):
    """Model for dict.items() - returns view of (key, value) pairs.
    Relationship: len(items) == len(dict)
    """

    name = "items"
    qualname = "dict.items"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return dict_type_error_result(self.name, state)
        d = get_symbolic_dict(args[0], state) if args else None
        if d is not None:
            return ModelResult(value=SymbolicDictView(f"dict_items_{state.pc}", d, "items"))
        result, constraint = SymbolicList.symbolic(f"dict_items_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class DictCopyModel(FunctionModel):
    """Model for dict.copy() - shallow copy.
    Relationship:
    - New dict has same length
    - New dict has same keys/values (shallow)
    """

    name = "copy"
    qualname = "dict.copy"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return dict_type_error_result(self.name, state)
        d = get_symbolic_dict(args[0], state) if args else None
        if d is not None:
            return ModelResult(value=d.copy())
        result, constraint = SymbolicDict.symbolic(f"dict_copy_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])
