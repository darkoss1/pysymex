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

"""Tier 3 path contradiction logic rules.

This package defines logic rules targeting Tier 3 path contradictions, including sequential
modular contradictions, post-assignment contradictions, return type contradictions, loop invariant
violations, and constraint narrowing contradictions.

Bug Class Detected:
    Logical contradiction (infeasible paths).

Required Evidence:
    Unsatisfiable cores violating path logic constraints.

Issue Kinds:
    IssueKind.LOGICAL_CONTRADICTION
"""

from .sequential_modular import SequentialModularRule
from .post_assignment import PostAssignmentContradictionRule
from .loop_invariant import LoopInvariantViolationRule
from .narrowing import NarrowingContradictionRule
from .return_type import ReturnTypeContradictionRule

__all__ = [
    "SequentialModularRule",
    "PostAssignmentContradictionRule",
    "LoopInvariantViolationRule",
    "NarrowingContradictionRule",
    "ReturnTypeContradictionRule",
]
