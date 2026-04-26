# pysymex: Python Symbolic Execution & Formal Verification
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


def wilson_upper_95(k: int, n: int) -> float:
    if n <= 0:
        return 0.0
    z = 1.96
    p = k / n
    denom = 1.0 + (z * z / n)
    center = p + (z * z) / (2 * n)
    spread = z * ((p * (1 - p) + (z * z) / (4 * n)) / n) ** 0.5
    return min(1.0, (center + spread) / denom)
