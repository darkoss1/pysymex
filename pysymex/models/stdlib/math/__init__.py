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

"""Symbolic models for the math standard library module."""

from __future__ import annotations

from pysymex.models.stdlib.math.numeric import (
    MathCosModel,
    MathFabsModel,
    MathGcdModel,
    MathSinModel,
    MathTanModel,
    MathRadiansModel,
    MathDegreesModel,
    MathCopysignModel,
)
from pysymex.models.stdlib.math.predicates import (
    MathIsCloseModel,
    MathIsfiniteModel,
    MathIsinfModel,
    MathIsnanModel,
)
from pysymex.models.stdlib.math.exponential import (
    MathExpModel,
    MathLogModel,
)
from pysymex.models.stdlib.math.roots import (
    MathCeilModel,
    MathFloorModel,
    MathSqrtModel,
    MathFactorialModel,
    MathTruncModel,
)

math_models = [
    MathSqrtModel(),
    MathCeilModel(),
    MathFloorModel(),
    MathLogModel(),
    MathExpModel(),
    MathSinModel(),
    MathCosModel(),
    MathTanModel(),
    MathFabsModel(),
    MathGcdModel(),
    MathIsfiniteModel(),
    MathIsinfModel(),
    MathIsnanModel(),
    MathIsCloseModel(),
    MathRadiansModel(),
    MathDegreesModel(),
    MathCopysignModel(),
    MathFactorialModel(),
    MathTruncModel(),
]

__all__ = [
    "MathCeilModel",
    "MathCosModel",
    "MathExpModel",
    "MathFabsModel",
    "MathFloorModel",
    "MathGcdModel",
    "MathIsCloseModel",
    "MathIsfiniteModel",
    "MathIsinfModel",
    "MathIsnanModel",
    "MathLogModel",
    "MathSinModel",
    "MathSqrtModel",
    "MathTanModel",
    "MathRadiansModel",
    "MathDegreesModel",
    "MathCopysignModel",
    "MathFactorialModel",
    "MathTruncModel",
    "math_models",
]
