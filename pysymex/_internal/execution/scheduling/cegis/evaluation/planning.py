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

"""Dry-run application planning for CEGIS shadow evaluation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.scheduling.cegis.application import plan_evidence_application
from pysymex._internal.execution.scheduling.cegis.outcomes.types import (
    EvidenceOutcome,
    EvidenceOutcomeKind,
)

from .types import ShadowDecisionEvaluation

if TYPE_CHECKING:
    from collections.abc import Mapping

    from pysymex._internal.execution.frontier.obligations.types import ObligationCapsule
    from pysymex._internal.execution.scheduling.cegis.bids.types import EvidenceAction
    from pysymex._internal.execution.scheduling.cegis.policy import SchedulerDecision


def planned_evaluation(
    decision: SchedulerDecision,
    outcome: EvidenceOutcome,
    *,
    selected_state_id: int | None,
    live_state_ids: tuple[int, ...],
    capsules_by_state_id: Mapping[int, ObligationCapsule],
) -> ShadowDecisionEvaluation:
    """Build the dry-run live-removal plan for an owner outcome."""
    plan = plan_evidence_application(
        outcome,
        live_state_ids=live_state_ids,
        capsules_by_state_id=capsules_by_state_id,
    )
    return ShadowDecisionEvaluation(
        decision=decision,
        outcome=outcome,
        application_plan=plan,
        selected_state_id=selected_state_id,
        explanation=outcome.explanation,
    )


def inconclusive_outcome(action: EvidenceAction, *, explanation: str) -> EvidenceOutcome:
    """Return a typed non-removing outcome for shadow-only unsupported actions."""
    return EvidenceOutcome(
        action=action,
        kind=EvidenceOutcomeKind.INCONCLUSIVE,
        explanation=explanation,
    )
