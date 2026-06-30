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

"""Configuration and precision helpers for Z3 floating-point analysis."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

import z3


class FloatPrecision(Enum):
    """Floating-point precision levels."""

    HALF = auto()
    SINGLE = auto()
    DOUBLE = auto()
    EXTENDED = auto()
    QUAD = auto()


def get_fp_sort(precision: FloatPrecision) -> z3.FPSortRef:
    """Get Z3 FP sort for a precision level."""
    if precision == FloatPrecision.HALF:
        return z3.FPSort(5, 11)
    if precision == FloatPrecision.SINGLE:
        return z3.Float32()
    if precision == FloatPrecision.DOUBLE:
        return z3.Float64()
    if precision == FloatPrecision.EXTENDED:
        return z3.FPSort(15, 64)
    if precision == FloatPrecision.QUAD:
        return z3.FPSort(15, 113)
    msg = f"unknown precision: {precision}"
    raise ValueError(msg)


@dataclass
class FloatConfig:
    """Configuration for floating-point analysis."""

    precision: FloatPrecision = FloatPrecision.DOUBLE
    rounding_mode: str = "RNE"
    check_underflow: bool = True
    check_overflow: bool = True

    def get_rounding_mode(self) -> z3.FPRMRef:
        """Get Z3 rounding mode."""
        modes = {
            "RNE": z3.RNE(),
            "RNA": z3.RNA(),
            "RTP": z3.RTP(),
            "RTN": z3.RTN(),
            "RTZ": z3.RTZ(),
        }
        return modes.get(self.rounding_mode, z3.RNE())
