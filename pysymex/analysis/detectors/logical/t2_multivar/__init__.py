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

"""Tier 2 Multi-Variable Logical Contradiction Rules.

Contains logic rules checking for contradictions involving relationships among
multiple variables, such as antisymmetry, triangle inequality, bounding sum, product sign,
and GCD impossibility.
"""

from .antisymmetry import AntisymmetryRule
from .triangle import TriangleImpossibilityRule
from .impossibility.sum import SumImpossibilityRule
from .product_sign import ProductSignContradictionRule
from .impossibility.gcd import GcdImpossibilityRule

__all__ = [
    "AntisymmetryRule",
    "TriangleImpossibilityRule",
    "SumImpossibilityRule",
    "ProductSignContradictionRule",
    "GcdImpossibilityRule",
]
