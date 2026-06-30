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

"""float instance method models."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.types.containers.tuples import SymbolicTuple
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    import z3

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class FloatIsIntegerModel(FunctionModel):
    """Model for float.is_integer()."""

    name = "is_integer"
    qualname = "float.is_integer"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        return ModelResult.bool(f"is_integer_{state.pc}")


class FloatRatioModel(FunctionModel):
    """Model for float.as_integer_ratio()."""

    name = "as_integer_ratio"
    qualname = "float.as_integer_ratio"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        num, num_cons = ModelResult.symbolic_int(f"float_ratio_n_{state.pc}")
        den, den_cons = ModelResult.symbolic_int(f"float_ratio_d_{state.pc}")

        from typing import cast

        result = SymbolicTuple.from_elements(num, den)
        constraints = [num_cons, den_cons, den.z3_int > 0]
        return ModelResult(
            value=cast("StackValue", result),
            constraints=cast("list[z3.ExprRef | z3.BoolRef]", constraints),
        )


class FloatHexModel(FunctionModel):
    """Model for float.hex() - returns hex string representation."""

    name = "hex"
    qualname = "float.hex"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        result, constraint = SymbolicString.symbolic(f"float_hex_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class FloatFromhexModel(FunctionModel):
    """Model for float.fromhex(s) - classmethod."""

    name = "fromhex"
    qualname = "float.fromhex"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        result, constraint = SymbolicValue.symbolic(f"fromhex_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class FloatConjugateModel(FunctionModel):
    """Model for float.conjugate() - returns self."""

    name = "conjugate"
    qualname = "float.conjugate"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        if args:
            return ModelResult(value=args[0])
        result, constraint = SymbolicValue.symbolic(f"conjugate_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])
