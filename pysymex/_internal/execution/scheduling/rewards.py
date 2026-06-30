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

"""Adaptive path reward scoring for execution scheduling."""

from __future__ import annotations


def calculate_path_reward(*, new_coverage: int, new_issues: int) -> float:
    """Return the adaptive scheduler reward for one executed path step."""
    reward = 0.0
    if new_issues > 0:
        reward += 10.0 * new_issues
    if new_coverage > 0:
        reward += 3.0 * new_coverage
    elif new_coverage == 0 and new_issues == 0:
        reward -= 0.5
    return reward
