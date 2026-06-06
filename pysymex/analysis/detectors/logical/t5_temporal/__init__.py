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

"""Tier 5 temporal logic rules.

This package defines logic rules targeting Tier 5 temporal logical contradictions,
including concurrency contradictions, resource state contradictions, and state impossibility.

Bug Class Detected:
    Logical contradiction (temporal/state violation).

Required Evidence:
    Unsatisfiable cores violating temporal, resource state, or state machine constraints.

Issue Kinds:
    IssueKind.LOGICAL_CONTRADICTION
"""

from .state_impossibility import StateImpossibilityRule
from .resource_state import ResourceStateContradictionRule
from .concurrency import ConcurrencyContradictionRule

__all__ = [
    "StateImpossibilityRule",
    "ResourceStateContradictionRule",
    "ConcurrencyContradictionRule",
]
