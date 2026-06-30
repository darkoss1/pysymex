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

"""Local CEGIS bid generation for a single frontier capsule."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.scheduling.cegis.bids.types import (
    EvidenceAction,
    EvidenceActionKind,
    EvidenceBid,
    EvidenceOwner,
)
from pysymex._internal.execution.scheduling.cegis.budgets import BudgetVector
from pysymex._internal.execution.scheduling.cegis.features import feature_vector_from_capsule

if TYPE_CHECKING:
    from pysymex._internal.execution.frontier.obligations.types import ObligationCapsule


def shadow_bids_for_capsule(
    capsule: ObligationCapsule,
    *,
    memory_pressure: float = 0.0,
) -> tuple[EvidenceBid, ...]:
    """Generate bounded phase-0 CEGIS bids without executing owner actions."""
    features = feature_vector_from_capsule(capsule, memory_pressure=memory_pressure)
    execute_budget = BudgetVector(
        wall_time_ms=1.0,
        resident_units=features.estimated_resident_units,
        reconstruction_units=features.estimated_reconstruct_units,
        path_budget=1,
    )
    bids = [
        EvidenceBid(
            action=EvidenceAction(
                action_id=f"{capsule.capsule_id}:execute",
                capsule_id=capsule.capsule_id,
                kind=EvidenceActionKind.EXECUTE_STEP,
                owner=EvidenceOwner.VM,
                required_budget=execute_budget,
            ),
            expected_detector_gain=float(features.detector_obligation_count),
            expected_coverage_gain=1.0,
            expected_core_reuse_gain=0.0,
            expected_dominance_gain=0.0,
            expected_pruned_units=0,
            expected_uncertainty_reduction=0.0,
            expected_cost=execute_budget,
            confidence=1.0,
            explanation="execute one exact VM step",
        ),
    ]
    if features.constraint_atom_count > 0:
        solver_budget = BudgetVector(wall_time_ms=2.0, solver_time_ms=1.0, path_budget=1)
        bids.append(
            EvidenceBid(
                action=EvidenceAction(
                    action_id=f"{capsule.capsule_id}:unsat_core",
                    capsule_id=capsule.capsule_id,
                    kind=EvidenceActionKind.TRY_UNSAT_CORE,
                    owner=EvidenceOwner.SOLVER,
                    required_budget=solver_budget,
                    may_remove_work=True,
                    requires_exact_evidence=True,
                ),
                expected_detector_gain=0.0,
                expected_coverage_gain=0.0,
                expected_core_reuse_gain=float(features.constraint_atom_count),
                expected_dominance_gain=0.0,
                expected_pruned_units=features.estimated_resident_units,
                expected_uncertainty_reduction=1.0,
                expected_cost=solver_budget,
                confidence=0.5,
                explanation="try exact UNSAT-core evidence",
            ),
        )
    return tuple(bids)
