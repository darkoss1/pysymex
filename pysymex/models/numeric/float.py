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
import z3

from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.core.types.containers.sequences import SymbolicTuple
from pysymex.models.builtins.base import FunctionModel, ModelResult
from pysymex.models.numeric.shared import numeric_type_error_result
from pysymex.models.typed_results import model_bool_result, symbolic_int_result

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


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
            return numeric_type_error_result(self.qualname, state)
        return model_bool_result(f"is_integer_{state.pc}")


class FloatAsIntegerRatioModel(FunctionModel):
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
            return numeric_type_error_result(self.qualname, state)
        num, num_cons = symbolic_int_result(f"float_ratio_n_{state.pc}")
        den, den_cons = symbolic_int_result(f"float_ratio_d_{state.pc}")

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
            return numeric_type_error_result(self.qualname, state)
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
            return numeric_type_error_result(self.qualname, state)
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
            return numeric_type_error_result(self.qualname, state)
        if args:
            return ModelResult(value=args[0])
        result, constraint = SymbolicValue.symbolic(f"conjugate_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


__all__ = [
    "FloatAsIntegerRatioModel",
    "FloatConjugateModel",
    "FloatFromhexModel",
    "FloatHexModel",
    "FloatIsIntegerModel",
]
