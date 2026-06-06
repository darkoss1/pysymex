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

"""Tier 4 interprocedural logic rules.

This package defines logic rules targeting Tier 4 interprocedural logical contradictions,
including api contract violations, postcondition contradictions, precondition impossibility,
and numeric range propagation contradictions.

Bug Class Detected:
    Logical contradiction (interprocedural contract violation).

Required Evidence:
    Unsatisfiable cores violating interprocedural/API constraints.

Issue Kinds:
    IssueKind.LOGICAL_CONTRADICTION
"""

from .postcondition import PostconditionContradictionRule
from .precondition import PreconditionImpossibilityRule
from .api_contract import ApiContractViolationRule
from .range_propagation import NumericRangePropagationRule

__all__ = [
    "PostconditionContradictionRule",
    "PreconditionImpossibilityRule",
    "ApiContractViolationRule",
    "NumericRangePropagationRule",
]
