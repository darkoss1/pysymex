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

"""Symbolic models for the :mod:`operator` module."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.capabilities import invoke_registered_model
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


@dataclass(frozen=True, slots=True)
class ItemGetterCallable:
    """Callable created by single-index ``operator.itemgetter``."""

    index: StackValue

    def __call__(self, value: object) -> object:
        _ = value
        result, _constraint = SymbolicValue.symbolic("itemgetter_result")
        return result


@dataclass(frozen=True, slots=True)
class AttrGetterCallable:
    """Callable created by a single plain-name ``operator.attrgetter``."""

    attr_name: str

    def __call__(self, value: object) -> object:
        _ = value
        result, _constraint = SymbolicValue.symbolic("attrgetter_result")
        return result


class ItemGetterModel(FunctionModel):
    """Model for operator.itemgetter()."""

    name = "itemgetter"
    qualname = "operator.itemgetter"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) == 1 and not kwargs:
            return ModelResult(value=ItemGetterCallable(args[0]))
        result, constraint = SymbolicValue.symbolic(f"itemgetter_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class AttrGetterModel(FunctionModel):
    """Model for operator.attrgetter()."""

    name = "attrgetter"
    qualname = "operator.attrgetter"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        attr_name = SymbolicString.concrete_literal(args[0]) if len(args) == 1 else None
        if attr_name is not None and "." not in attr_name and not kwargs:
            return ModelResult(value=AttrGetterCallable(attr_name))
        result, constraint = SymbolicValue.symbolic(f"attrgetter_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OperatorAddModel(FunctionModel):
    """Model for operator.add()."""

    name = "add"
    qualname = "operator.add"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
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
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
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
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) >= 2:
            a, b = args[0], args[1]
            if isinstance(a, SymbolicValue) and isinstance(b, SymbolicValue):
                return ModelResult(value=a * b)
            if isinstance(a, (int, float)) and isinstance(b, (int, float)):
                return ModelResult(value=SymbolicValue.from_const(a * b))
        result, constraint = SymbolicValue.symbolic(f"op_mul_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OperatorIaddModel(FunctionModel):
    """Model for operator.iadd()."""

    name = "iadd"
    qualname = "operator.iadd"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) == 2 and not kwargs:
            delegated = invoke_registered_model("list.__iadd__", args, kwargs, state)
            if delegated is not None:
                return delegated
        result, constraint = SymbolicValue.symbolic(f"op_iadd_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OperatorIconcatModel(FunctionModel):
    """Model for operator.iconcat()."""

    name = "iconcat"
    qualname = "operator.iconcat"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) == 2 and not kwargs:
            delegated = invoke_registered_model("list.__iadd__", args, kwargs, state)
            if delegated is not None:
                return delegated
        result, constraint = SymbolicValue.symbolic(f"op_iconcat_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OperatorImulModel(FunctionModel):
    """Model for operator.imul()."""

    name = "imul"
    qualname = "operator.imul"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) == 2 and not kwargs:
            delegated = invoke_registered_model("list.__imul__", args, kwargs, state)
            if delegated is not None:
                return delegated
        result, constraint = SymbolicValue.symbolic(f"op_imul_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OperatorTruedivModel(FunctionModel):
    """Model for operator.truediv()."""

    name = "truediv"
    qualname = "operator.truediv"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
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
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
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
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
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
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if args and isinstance(args[0], SymbolicValue):
            return ModelResult(value=-args[0])
        result, constraint = SymbolicValue.symbolic(f"op_neg_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


operator_models = [
    ItemGetterModel(),
    AttrGetterModel(),
    OperatorAddModel(),
    OperatorSubModel(),
    OperatorMulModel(),
    OperatorIaddModel(),
    OperatorIconcatModel(),
    OperatorImulModel(),
    OperatorTruedivModel(),
    OperatorFloordivModel(),
    OperatorModModel(),
    OperatorNegModel(),
]
