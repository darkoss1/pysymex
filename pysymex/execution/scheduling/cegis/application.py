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

"""Evidence-application planning for CEGIS owner outcomes."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from pysymex.execution.frontier import ObligationCapsule
from pysymex.execution.scheduling.cegis.outcomes import EvidenceOutcome

__all__ = ["EvidenceApplicationPlan", "plan_evidence_application"]


@dataclass(frozen=True, slots=True)
class EvidenceApplicationPlan:
    """Dry-run plan for applying a CEGIS owner outcome to live frontier work."""

    outcome: EvidenceOutcome
    removable_state_ids: tuple[int, ...]
    removable_capsule_ids: tuple[str, ...]
    invalid_removal_attempt: bool
    explanation: str

    @property
    def can_remove(self) -> bool:
        """Return whether this plan identifies live states that may be removed."""
        return bool(self.removable_state_ids) and not self.invalid_removal_attempt


def plan_evidence_application(
    outcome: EvidenceOutcome,
    *,
    live_state_ids: Iterable[int],
    capsules_by_state_id: Mapping[int, ObligationCapsule],
) -> EvidenceApplicationPlan:
    """Plan live-state removal for a typed owner outcome without mutating the frontier."""
    if outcome.has_invalid_removal_attempt:
        return EvidenceApplicationPlan(
            outcome=outcome,
            removable_state_ids=(),
            removable_capsule_ids=(),
            invalid_removal_attempt=True,
            explanation="outcome attempted removal outside exact certificate coverage",
        )

    valid_capsule_ids = frozenset(outcome.valid_removed_capsule_ids)
    if not valid_capsule_ids:
        return EvidenceApplicationPlan(
            outcome=outcome,
            removable_state_ids=(),
            removable_capsule_ids=(),
            invalid_removal_attempt=False,
            explanation="outcome has no certificate-covered removals",
        )

    live_ids = frozenset(live_state_ids)
    removable_state_ids: list[int] = []
    removable_capsule_ids: list[str] = []
    for state_id, capsule in sorted(capsules_by_state_id.items()):
        if state_id in live_ids and capsule.capsule_id in valid_capsule_ids:
            removable_state_ids.append(state_id)
            removable_capsule_ids.append(capsule.capsule_id)

    return EvidenceApplicationPlan(
        outcome=outcome,
        removable_state_ids=tuple(removable_state_ids),
        removable_capsule_ids=tuple(removable_capsule_ids),
        invalid_removal_attempt=False,
        explanation="certificate-covered live states identified",
    )
