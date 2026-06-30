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

"""Structured detector feasibility result types.

This module owns model-evidence classification for detector queries. Solver and
witness mechanics live in sibling evidence modules and the detector feasibility
coordinator.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import z3


class FeasibilityModelStatus(Enum):
    """Structured detector model-evidence outcomes."""

    SAT = auto()
    NO_SAT_EVIDENCE = auto()
    INCONCLUSIVE = auto()


@dataclass(frozen=True, slots=True)
class FeasibilityModelResult:
    """Model-backed detector feasibility evidence.

    ``NO_SAT_EVIDENCE`` means the supplied boolean callback did not establish
    a satisfiable path. It must not be presented as a proof of UNSAT unless
    the callback contract is known to make that stronger claim.
    """

    status: FeasibilityModelStatus
    model: z3.ModelRef | dict[str, object] | None = None
    reason: str | None = None

    @property
    def is_sat(self) -> bool:
        """Return whether a SAT model or witness is present."""
        return self.status is FeasibilityModelStatus.SAT

    @property
    def is_inconclusive(self) -> bool:
        """Return whether feasibility or model extraction was inconclusive."""
        return self.status is FeasibilityModelStatus.INCONCLUSIVE

    @staticmethod
    def sat(model: z3.ModelRef | dict[str, object]) -> FeasibilityModelResult:
        """Create a SAT model or concrete-witness result."""
        return FeasibilityModelResult(FeasibilityModelStatus.SAT, model)

    @staticmethod
    def no_sat_evidence(reason: str) -> FeasibilityModelResult:
        """Create a result for absent SAT evidence from the callback."""
        return FeasibilityModelResult(FeasibilityModelStatus.NO_SAT_EVIDENCE, reason=reason)

    @staticmethod
    def inconclusive(reason: str) -> FeasibilityModelResult:
        """Create an inconclusive detector feasibility result."""
        return FeasibilityModelResult(FeasibilityModelStatus.INCONCLUSIVE, reason=reason)
