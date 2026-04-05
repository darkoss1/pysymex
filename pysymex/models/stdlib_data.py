# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Symbolic models for enum, dataclasses, and operator modules.

Models:
- enum: Enum, IntEnum, auto, value, name
- dataclasses: dataclass, field, asdict, astuple, fields, replace
- operator: itemgetter, attrgetter, add, sub, mul, truediv, floordiv, mod, neg
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.core.addressing import next_address
from pysymex.core.types import (
    SymbolicDict,
    SymbolicList,
    SymbolicObject,
    SymbolicString,
    SymbolicValue,
)
from pysymex.models.builtins import FunctionModel, ModelResult

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState


class EnumModel(FunctionModel):
    """Model for enum.Enum class construction."""

    name = "Enum"
    qualname = "enum.Enum"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"enum_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


class IntEnumModel(FunctionModel):
    """Model for enum.IntEnum class construction."""

    name = "IntEnum"
    qualname = "enum.IntEnum"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"intenum_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


class EnumAutoModel(FunctionModel):
    """Model for enum.auto() to generate enum values."""

    name = "auto"
    qualname = "enum.auto"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"enum_auto_{state.pc}")
        return ModelResult(
            value=result, constraints=[constraint, result.is_int, result.z3_int >= 1]
        )


class EnumValueModel(FunctionModel):
    """Model for accessing Enum.value property."""

    name = "value"
    qualname = "enum.Enum.value"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"enum_value_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class EnumNameModel(FunctionModel):
    """Model for accessing Enum.name property."""

    name = "name"
    qualname = "enum.Enum.name"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"enum_name_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


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


class OperatorItemgetterModel(FunctionModel):
    """Model for operator.itemgetter()."""

    name = "itemgetter"
    qualname = "operator.itemgetter"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"itemgetter_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OperatorAttrgetterModel(FunctionModel):
    """Model for operator.attrgetter()."""

    name = "attrgetter"
    qualname = "operator.attrgetter"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"attrgetter_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OperatorAddModel(FunctionModel):
    """Model for operator.add()."""

    name = "add"
    qualname = "operator.add"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if len(args) >= 2:
            a, b = args[0], args[1]
            if isinstance(a, SymbolicValue) and isinstance(b, SymbolicValue):
                return ModelResult(value=a + b)
            if isinstance(a, (int, float)) and isinstance(b, (int, float)):
                return ModelResult(value=SymbolicValue.from_const(a + b))
        result, constraint = SymbolicValue.symbolic(f"op_add_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OperatorSubModel(FunctionModel):
    """Model for operator.sub()."""

    name = "sub"
    qualname = "operator.sub"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if len(args) >= 2:
            a, b = args[0], args[1]
            if isinstance(a, SymbolicValue) and isinstance(b, SymbolicValue):
                return ModelResult(value=a - b)
            if isinstance(a, (int, float)) and isinstance(b, (int, float)):
                return ModelResult(value=SymbolicValue.from_const(a - b))
        result, constraint = SymbolicValue.symbolic(f"op_sub_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OperatorMulModel(FunctionModel):
    """Model for operator.mul()."""

    name = "mul"
    qualname = "operator.mul"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if len(args) >= 2:
            a, b = args[0], args[1]
            if isinstance(a, SymbolicValue) and isinstance(b, SymbolicValue):
                return ModelResult(value=a * b)
            if isinstance(a, (int, float)) and isinstance(b, (int, float)):
                return ModelResult(value=SymbolicValue.from_const(a * b))
        result, constraint = SymbolicValue.symbolic(f"op_mul_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OperatorTruedivModel(FunctionModel):
    """Model for operator.truediv()."""

    name = "truediv"
    qualname = "operator.truediv"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if len(args) >= 2:
            a, b = args[0], args[1]
            if isinstance(a, SymbolicValue) and isinstance(b, SymbolicValue):
                return ModelResult(value=a / b)
        result, constraint = SymbolicValue.symbolic(f"op_truediv_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OperatorFloordivModel(FunctionModel):
    """Model for operator.floordiv()."""

    name = "floordiv"
    qualname = "operator.floordiv"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if len(args) >= 2:
            a, b = args[0], args[1]
            if isinstance(a, SymbolicValue) and isinstance(b, SymbolicValue):
                return ModelResult(value=a // b)
        result, constraint = SymbolicValue.symbolic(f"op_floordiv_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OperatorModModel(FunctionModel):
    """Model for operator.mod()."""

    name = "mod"
    qualname = "operator.mod"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if len(args) >= 2:
            a, b = args[0], args[1]
            if isinstance(a, SymbolicValue) and isinstance(b, SymbolicValue):
                return ModelResult(value=a % b)
        result, constraint = SymbolicValue.symbolic(f"op_mod_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OperatorNegModel(FunctionModel):
    """Model for operator.neg()."""

    name = "neg"
    qualname = "operator.neg"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if args and isinstance(args[0], SymbolicValue):
            return ModelResult(value=-args[0])
        result, constraint = SymbolicValue.symbolic(f"op_neg_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


enum_models = [
    EnumModel(),
    IntEnumModel(),
    EnumAutoModel(),
    EnumValueModel(),
    EnumNameModel(),
]
dataclasses_models = [
    DataclassModel(),
    DataclassFieldModel(),
    AsDataclassModel(),
    AstupleModel(),
    FieldsModel(),
    ReplaceModel(),
]
operator_models = [
    OperatorItemgetterModel(),
    OperatorAttrgetterModel(),
    OperatorAddModel(),
    OperatorSubModel(),
    OperatorMulModel(),
    OperatorTruedivModel(),
    OperatorFloordivModel(),
    OperatorModModel(),
    OperatorNegModel(),
]
