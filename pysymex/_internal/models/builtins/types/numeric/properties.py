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

"""Property-like numeric method models."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


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


class ComplexRealModel(FunctionModel):
    name = "real"
    qualname = "complex.real"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Return the real part of the complex number."""
        from pysymex._internal.core.types.scalars.values import SymbolicValue

        result, constraint = SymbolicValue.symbolic(f"complex_real_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class ComplexImagModel(FunctionModel):
    name = "imag"
    qualname = "complex.imag"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Return the imaginary part of the complex number."""
        from pysymex._internal.core.types.scalars.values import SymbolicValue

        result, constraint = SymbolicValue.symbolic(f"complex_imag_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


NUMERIC_PROPERTY_MODELS: list[FunctionModel] = [
    IntNumeratorModel(),
    IntDenominatorModel(),
    IntRealModel(),
    IntImagModel(),
    FloatRealModel(),
    FloatImagModel(),
    ComplexRealModel(),
    ComplexImagModel(),
]
