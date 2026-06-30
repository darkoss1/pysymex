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

"""Selected-bid CEGIS shadow evaluation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.scheduling.cegis.bids.types import EvidenceOwner
from pysymex._internal.execution.scheduling.cegis.evaluation.live import (
    CheckpointLoader,
    find_live_capsule_state_id,
)

from .owners import choose_frontier_owner_action, choose_solver_owner_action
from .planning import inconclusive_outcome, planned_evaluation
from .types import ShadowDecisionEvaluation

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from pysymex._internal.execution.frontier.checkpoints import FrontierCheckpoint
    from pysymex._internal.execution.frontier.obligations.types import ObligationCapsule
    from pysymex._internal.execution.scheduling.cegis.policy import SchedulerDecision


def evaluate_shadow_decision(
    decision: SchedulerDecision | None,
    *,
    live_state_ids: Iterable[int],
    capsules_by_state_id: Mapping[int, ObligationCapsule],
    checkpoints_by_state_id: Mapping[int, FrontierCheckpoint],
    checkpoint_loader: CheckpointLoader | None = None,
    solver_timeout_ms: int = 10000,
    unsat_core_timeout_ms: int = 5000,
) -> ShadowDecisionEvaluation:
    """Evaluate one selected CEGIS bid through its owner without mutating live work.

    CEGIS may select an evidence action, but solver/frontier owners still decide
    whether exact proof exists. The returned application plan is a dry run of
    that outcome against live capsules; runtime callers must invoke a separate
    frontier mutation method to consume certificate-backed removals.
    """
    live_state_id_tuple = tuple(live_state_ids)
    if decision is None:
        return ShadowDecisionEvaluation(
            decision=None,
            outcome=None,
            application_plan=None,
            selected_state_id=None,
            explanation="no CEGIS bid selected",
        )

    action = decision.selected_bid.action
    selected_state_id = find_live_capsule_state_id(
        action.capsule_id,
        live_state_ids=live_state_id_tuple,
        capsules_by_state_id=capsules_by_state_id,
    )
    if selected_state_id is None:
        outcome = inconclusive_outcome(
            action,
            explanation="selected capsule is not live",
        )
        return planned_evaluation(
            decision,
            outcome,
            selected_state_id=None,
            live_state_ids=live_state_id_tuple,
            capsules_by_state_id=capsules_by_state_id,
        )

    if action.owner is EvidenceOwner.SOLVER:
        outcome = choose_solver_owner_action(
            action,
            selected_state_id=selected_state_id,
            live_state_ids=live_state_id_tuple,
            checkpoints_by_state_id=checkpoints_by_state_id,
            checkpoint_loader=checkpoint_loader,
            solver_timeout_ms=solver_timeout_ms,
            unsat_core_timeout_ms=unsat_core_timeout_ms,
        )
    elif action.owner is EvidenceOwner.FRONTIER:
        outcome = choose_frontier_owner_action(
            action,
            selected_state_id=selected_state_id,
            live_state_ids=live_state_id_tuple,
            checkpoints_by_state_id=checkpoints_by_state_id,
            checkpoint_loader=checkpoint_loader,
        )
    else:
        outcome = inconclusive_outcome(
            action,
            explanation="shadow evaluation does not execute this owner action",
        )

    return planned_evaluation(
        decision,
        outcome,
        selected_state_id=selected_state_id,
        live_state_ids=live_state_id_tuple,
        capsules_by_state_id=capsules_by_state_id,
    )
