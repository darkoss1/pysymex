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

"""Symbolic models for numeric (int, float, complex) instance methods."""

from __future__ import annotations

from pysymex.models.numeric.complex import ComplexConjugateModel
from pysymex.models.numeric.float import (
    FloatAsIntegerRatioModel,
    FloatConjugateModel,
    FloatFromhexModel,
    FloatHexModel,
    FloatIsIntegerModel,
)
from pysymex.models.numeric.int import (
    IntAsIntegerRatioModel,
    IntBitCountModel,
    IntBitLengthModel,
    IntConjugateModel,
    IntFromBytesModel,
    IntToBytesModel,
)
from pysymex.models.numeric.properties import (
    ComplexImagModel,
    ComplexRealModel,
    FloatImagModel,
    FloatRealModel,
    IntDenominatorModel,
    IntImagModel,
    IntNumeratorModel,
    IntRealModel,
    NUMERIC_PROPERTY_MODELS,
)

INT_FLOAT_MODELS = [
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
    ComplexConjugateModel(),
    *NUMERIC_PROPERTY_MODELS,
]

__all__ = [
    "ComplexConjugateModel",
    "ComplexImagModel",
    "ComplexRealModel",
    "FloatAsIntegerRatioModel",
    "FloatConjugateModel",
    "FloatFromhexModel",
    "FloatHexModel",
    "FloatImagModel",
    "FloatIsIntegerModel",
    "FloatRealModel",
    "INT_FLOAT_MODELS",
    "IntAsIntegerRatioModel",
    "IntBitCountModel",
    "IntBitLengthModel",
    "IntConjugateModel",
    "IntDenominatorModel",
    "IntFromBytesModel",
    "IntImagModel",
    "IntNumeratorModel",
    "IntRealModel",
    "IntToBytesModel",
]
