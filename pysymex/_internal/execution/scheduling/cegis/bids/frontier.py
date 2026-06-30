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

"""Live-frontier CEGIS bid generation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.frontier.obligations.digests import capsule_semantic_digest
from pysymex._internal.execution.scheduling.cegis.bids.capsules import shadow_bids_for_capsule
from pysymex._internal.execution.scheduling.cegis.bids.types import (
    EvidenceAction,
    EvidenceActionKind,
    EvidenceBid,
    EvidenceOwner,
)
from pysymex._internal.execution.scheduling.cegis.budgets import BudgetVector
from pysymex._internal.execution.scheduling.cegis.features import feature_vector_from_capsule

if TYPE_CHECKING:
    from collections.abc import Iterable

    from pysymex._internal.execution.frontier.obligations.types import (
        CapsuleDigest,
        ObligationCapsule,
    )


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
        ),
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
            ),
        )

    return tuple(bids)
