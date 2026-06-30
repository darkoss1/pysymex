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

"""int instance method models."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.tuples import SymbolicTuple
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class IntBitLengthModel(FunctionModel):
    """Model for int.bit_length() - number of bits needed to represent the int."""

    name = "bit_length"
    qualname = "int.bit_length"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Return a faithful concrete result for Python ints and safe symbolic constraints otherwise."""
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        if args and isinstance(args[0], int):
            return ModelResult(value=args[0].bit_length())

        result, constraints = ModelResult.symbolic_int(f"bit_length_{state.pc}")
        constraints.append(result.z3_int >= 0)
        if args:
            val: z3.ArithRef | None = getattr(args[0], "z3_int", None)
            if val is not None:
                abs_val: z3.ArithRef = z3.If(val < 0, -val, val)
                constraints.append(z3.Implies(abs_val == 0, result.z3_int == 0))
                constraints.append(z3.Implies(abs_val > 0, result.z3_int >= 1))
        return ModelResult(value=result, constraints=constraints)


class IntBitCountModel(FunctionModel):
    """Model for int.bit_count() - number of 1 bits (Python 3.10+)."""

    name = "bit_count"
    qualname = "int.bit_count"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Return a faithful concrete result for Python ints and safe symbolic constraints otherwise."""
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        if args and isinstance(args[0], int):
            return ModelResult(value=args[0].bit_count())

        result, constraints = ModelResult.symbolic_int(f"bit_count_{state.pc}")
        constraints.append(result.z3_int >= 0)
        if args:
            val: z3.ArithRef | None = getattr(args[0], "z3_int", None)
            if val is not None:
                abs_val: z3.ArithRef = z3.If(val < 0, -val, val)
                constraints.append(z3.Implies(abs_val == 0, result.z3_int == 0))
        return ModelResult(value=result, constraints=constraints)


class IntToBytesModel(FunctionModel):
    """Model for int.to_bytes(length, byteorder)."""

    name = "to_bytes"
    qualname = "int.to_bytes"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if (
            len(args) not in {1, 2, 3}
            or set(kwargs) - {"length", "byteorder", "signed"}
            or (len(args) > 1 and "length" in kwargs)
            or (len(args) > 2 and "byteorder" in kwargs)
        ):
            return ModelResult.method_type_error(self.qualname, state)
        result, constraint = SymbolicList.symbolic(f"to_bytes_{state.pc}")
        constraints = [constraint]
        if len(args) > 1:
            length = getattr(args[1], "z3_int", None)
            if length is not None:
                constraints.append(result.z3_len == length)
        return ModelResult(value=result, constraints=constraints)


class IntFromBytesModel(FunctionModel):
    """Model for int.from_bytes(bytes, byteorder) - classmethod."""

    name = "from_bytes"
    qualname = "int.from_bytes"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if (
            len(args) not in {0, 1, 2}
            or set(kwargs) - {"bytes", "byteorder", "signed"}
            or (not args and "bytes" not in kwargs)
            or (args and "bytes" in kwargs)
            or (len(args) > 1 and "byteorder" in kwargs)
        ):
            return ModelResult.method_type_error(self.qualname, state)
        return ModelResult.int(f"from_bytes_{state.pc}")


class IntAsIntegerRatioModel(FunctionModel):
    """Model for int.as_integer_ratio() - returns (self, 1)."""

    name = "as_integer_ratio"
    qualname = "int.as_integer_ratio"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        if args:
            self_val = args[0]
        else:
            self_val, _ = ModelResult.symbolic_int(f"int_ratio_self_{state.pc}")

        from typing import cast

        result = SymbolicTuple.from_elements(self_val, 1)
        return ModelResult(value=cast("StackValue", result), constraints=[])


class IntConjugateModel(FunctionModel):
    """Model for int.conjugate() - returns self."""

    name = "conjugate"
    qualname = "int.conjugate"

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
        return ModelResult.int(f"conjugate_{state.pc}")
