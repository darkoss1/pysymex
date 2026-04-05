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

"""Symbolic models for int and float instance methods.

Provides models for int.bit_length, int.bit_count, int.to_bytes, int.from_bytes,
int.as_integer_ratio, float.is_integer, float.as_integer_ratio, float.hex, etc.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex.core.types import SymbolicList, SymbolicString, SymbolicValue
from pysymex.models.builtins_base import FunctionModel, ModelResult

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState


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
        result, constraint = SymbolicValue.symbolic(f"bit_length_{state.pc}")
        constraints = [constraint, result.is_int, result.z3_int >= 0]
        if args:
            val = getattr(args[0], "z3_int", None)
            if val is not None:
                constraints.append(z3.Implies(val == 0, result.z3_int == 0))
                constraints.append(z3.Implies(val != 0, result.z3_int >= 1))
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
        result, constraint = SymbolicValue.symbolic(f"bit_count_{state.pc}")
        constraints = [constraint, result.is_int, result.z3_int >= 0]
        if args:
            val = getattr(args[0], "z3_int", None)
            if val is not None:
                constraints.append(z3.Implies(val == 0, result.z3_int == 0))
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
        result, constraint = SymbolicValue.symbolic(f"from_bytes_{state.pc}")
        constraints = [constraint, result.is_int]
        return ModelResult(value=result, constraints=constraints)


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
        result, constraint = SymbolicList.symbolic(f"int_ratio_{state.pc}")
        constraints = [constraint, result.z3_len == 2]
        return ModelResult(value=result, constraints=constraints)


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
        if args:
            return ModelResult(value=args[0])
        result, constraint = SymbolicValue.symbolic(f"conjugate_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


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
        result, constraint = SymbolicValue.symbolic(f"is_integer_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


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
        result, constraint = SymbolicList.symbolic(f"float_ratio_{state.pc}")
        constraints = [constraint, result.z3_len == 2]
        return ModelResult(value=result, constraints=constraints)


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
        if args:
            return ModelResult(value=args[0])
        result, constraint = SymbolicValue.symbolic(f"conjugate_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


INT_FLOAT_MODELS: list[FunctionModel] = [
    IntBitLengthModel(),
    IntBitCountModel(),
    IntToBytesModel(),
    IntFromBytesModel(),
    IntAsIntegerRatioModel(),
    IntConjugateModel(),
    FloatIsIntegerModel(),
    FloatAsIntegerRatioModel(),
    FloatHexModel(),
    FloatFromhexModel(),
    FloatConjugateModel(),
]


class IntNumeratorModel(FunctionModel):
    name = "numerator"
    qualname = "int.numerator"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Return the numerator of the integer (always self)."""
        if not args:
            return ModelResult(1, [], {})
        return ModelResult(args[0], [], {})


class IntDenominatorModel(FunctionModel):
    name = "denominator"
    qualname = "int.denominator"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Return the denominator of the integer (always 1)."""
        return ModelResult(1, [], {})


class IntRealModel(FunctionModel):
    name = "real"
    qualname = "int.real"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Return the real part of the integer (always self)."""
        if not args:
            return ModelResult(0, [], {})
        return ModelResult(args[0], [], {})


class IntImagModel(FunctionModel):
    name = "imag"
    qualname = "int.imag"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Return the imaginary part of the integer (always 0)."""
        return ModelResult(0, [], {})


class FloatRealModel(FunctionModel):
    name = "real"
    qualname = "float.real"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Return the real part of the float (always self)."""
        if not args:
            return ModelResult(0.0, [], {})
        return ModelResult(args[0], [], {})


class FloatImagModel(FunctionModel):
    name = "imag"
    qualname = "float.imag"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Return the imaginary part of the float (always 0.0)."""
        return ModelResult(0.0, [], {})


INT_FLOAT_MODELS.extend(
    [
        IntNumeratorModel(),
        IntDenominatorModel(),
        IntRealModel(),
        IntImagModel(),
        FloatRealModel(),
        FloatImagModel(),
    ]
)
