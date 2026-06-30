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

"""Typed phase-0 CEGIS bid records."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex._internal.execution.scheduling.cegis.budgets import BudgetVector


class EvidenceActionKind(Enum):
    """Typed action families available to CEGIS shadow bidding."""

    EXECUTE_STEP = "execute_step"
    TRY_UNSAT_CORE = "try_unsat_core"
    CHECK_DOMINANCE = "check_dominance"


class EvidenceOwner(Enum):
    """Subsystem that owns the truth for a selected action."""

    VM = "vm"
    SOLVER = "solver"
    FRONTIER = "frontier"


@dataclass(frozen=True, slots=True)
class EvidenceAction:
    """Candidate action CEGIS may rank but cannot treat as truth."""

    action_id: str
    capsule_id: str
    kind: EvidenceActionKind
    owner: EvidenceOwner
    required_budget: BudgetVector
    may_remove_work: bool = False
    requires_exact_evidence: bool = False

    @property
    def is_sound_for_selection(self) -> bool:
        """Return whether this shadow action can be selected by policy.

        CEGIS may only select work-removing actions when the owning subsystem
        must produce exact evidence before any live work is discarded.
        """
        return not self.may_remove_work or self.requires_exact_evidence


@dataclass(frozen=True, slots=True)
class EvidenceBid:
    """Costed action proposal emitted by the phase-0 proof market."""

    action: EvidenceAction
    expected_detector_gain: float
    expected_coverage_gain: float
    expected_core_reuse_gain: float
    expected_dominance_gain: float
    expected_pruned_units: int
    expected_uncertainty_reduction: float
    expected_cost: BudgetVector
    confidence: float
    explanation: str

    @property
    def score(self) -> float:
        """Return a deterministic utility score for shadow selection."""
        gain = (
            self.expected_detector_gain
            + self.expected_coverage_gain
            + self.expected_core_reuse_gain
            + self.expected_dominance_gain
            + self.expected_uncertainty_reduction
            + float(self.expected_pruned_units)
        )
        cost = (
            self.expected_cost.wall_time_ms
            + self.expected_cost.solver_time_ms
            + float(self.expected_cost.reconstruction_units)
        )
        return gain - cost
