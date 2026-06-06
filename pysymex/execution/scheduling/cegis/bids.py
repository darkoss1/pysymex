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

"""Phase-0 CEGIS bid records and shadow bid generation."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from pysymex.execution.frontier import CapsuleDigest, ObligationCapsule, capsule_semantic_digest
from pysymex.execution.scheduling.cegis.budgets import BudgetVector
from pysymex.execution.scheduling.cegis.features import feature_vector_from_capsule


class EvidenceActionKind(Enum):
    """Typed action families available to CEGIS shadow bidding."""

    EXECUTE_STEP = "execute_step"
    TRY_UNSAT_CORE = "try_unsat_core"
    CHECK_DOMINANCE = "check_dominance"
    REFINE_FOOTPRINT = "refine_footprint"
    PROBE_DETECTOR = "probe_detector"


class EvidenceOwner(Enum):
    """Subsystem that owns the truth for a selected action."""

    VM = "vm"
    SOLVER = "solver"
    FRONTIER = "frontier"
    DETECTOR = "detector"


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
        )
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
            )
        )
    return tuple(bids)


def shadow_bids_for_frontier_capsules(
    capsules: Iterable[ObligationCapsule],
    *,
    memory_pressure: float = 0.0,
) -> tuple[EvidenceBid, ...]:
    """Generate CEGIS bids that need live-frontier context.

    Per-capsule bids remain local. Exact dominance bids are generated only when
    the live frontier contains structurally duplicate capsules, because a
    standalone capsule cannot prove any sibling coverage.
    """
    capsule_tuple = tuple(capsules)
    bids = [
        bid
        for capsule in capsule_tuple
        for bid in shadow_bids_for_capsule(capsule, memory_pressure=memory_pressure)
    ]
    bids.extend(
        _dominance_bids_for_duplicate_capsules(
            capsule_tuple,
            memory_pressure=memory_pressure,
        )
    )
    return tuple(bids)


def _dominance_bids_for_duplicate_capsules(
    capsules: tuple[ObligationCapsule, ...],
    *,
    memory_pressure: float,
) -> tuple[EvidenceBid, ...]:
    """Return exact-dominance bids for deterministic duplicate-capsule groups."""
    groups: dict[CapsuleDigest, list[ObligationCapsule]] = {}
    for capsule in capsules:
        groups.setdefault(capsule_semantic_digest(capsule), []).append(capsule)

    bids: list[EvidenceBid] = []
    for group in groups.values():
        if len(group) < 2:
            continue

        subject = group[0]
        dominated = group[1:]
        features = feature_vector_from_capsule(subject, memory_pressure=memory_pressure)
        dominated_units = sum(max(1, capsule.estimated_resident_units) for capsule in dominated)
        dominance_budget = BudgetVector(
            wall_time_ms=1.0,
            resident_units=features.estimated_resident_units + dominated_units,
            reconstruction_units=features.estimated_reconstruct_units,
            path_budget=1,
        )
        bids.append(
            EvidenceBid(
                action=EvidenceAction(
                    action_id=f"{subject.capsule_id}:dominance",
                    capsule_id=subject.capsule_id,
                    kind=EvidenceActionKind.CHECK_DOMINANCE,
                    owner=EvidenceOwner.FRONTIER,
                    required_budget=dominance_budget,
                    may_remove_work=True,
                    requires_exact_evidence=True,
                ),
                expected_detector_gain=0.0,
                expected_coverage_gain=0.0,
                expected_core_reuse_gain=0.0,
                expected_dominance_gain=float(len(dominated) + dominated_units),
                expected_pruned_units=dominated_units,
                expected_uncertainty_reduction=1.0,
                expected_cost=dominance_budget,
                confidence=1.0,
                explanation="check exact checkpoint duplicate dominance",
            )
        )

    return tuple(bids)
