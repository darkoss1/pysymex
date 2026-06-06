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

"""Shadow CEGIS decision evaluation and dry-run planning."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass

from pysymex.execution.frontier import FrontierCheckpoint, ObligationCapsule
from pysymex.execution.scheduling.cegis.application import (
    EvidenceApplicationPlan,
    plan_evidence_application,
)
from pysymex.execution.scheduling.cegis.bids import (
    EvidenceAction,
    EvidenceOwner,
    shadow_bids_for_frontier_capsules,
)
from pysymex.execution.scheduling.cegis.budgets import BudgetVector
from pysymex.execution.scheduling.cegis.outcomes import EvidenceOutcome, EvidenceOutcomeKind
from pysymex.execution.scheduling.cegis.owners import (
    evaluate_checkpoint_dominance_action,
    evaluate_checkpoint_unsat_core_action,
)
from pysymex.execution.scheduling.cegis.policy import (
    SchedulerDecision,
    select_deterministic_bid,
)

__all__ = [
    "ShadowDecisionEvaluation",
    "evaluate_shadow_decision",
    "evaluate_shadow_frontier",
]

_CheckpointLoader = Callable[[int], FrontierCheckpoint | None]


@dataclass(frozen=True, slots=True)
class ShadowDecisionEvaluation:
    """Non-mutating result of evaluating a selected CEGIS shadow decision."""

    decision: SchedulerDecision | None
    outcome: EvidenceOutcome | None
    application_plan: EvidenceApplicationPlan | None
    selected_state_id: int | None
    explanation: str

    @property
    def has_decision(self) -> bool:
        """Return whether a CEGIS bid was selected for evaluation."""
        return self.decision is not None

    @property
    def can_remove(self) -> bool:
        """Return whether the owner outcome has certificate-backed live removals."""
        return self.application_plan is not None and self.application_plan.can_remove


def evaluate_shadow_decision(
    decision: SchedulerDecision | None,
    *,
    live_state_ids: Iterable[int],
    capsules_by_state_id: Mapping[int, ObligationCapsule],
    checkpoints_by_state_id: Mapping[int, FrontierCheckpoint],
    checkpoint_loader: _CheckpointLoader | None = None,
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
    selected_state_id = _find_live_capsule_state_id(
        action.capsule_id,
        live_state_ids=live_state_id_tuple,
        capsules_by_state_id=capsules_by_state_id,
    )
    if selected_state_id is None:
        outcome = _inconclusive_outcome(
            action,
            explanation="selected capsule is not live",
        )
        return _planned_evaluation(
            decision,
            outcome,
            selected_state_id=None,
            live_state_ids=live_state_id_tuple,
            capsules_by_state_id=capsules_by_state_id,
        )

    if action.owner is EvidenceOwner.SOLVER:
        outcome = _evaluate_solver_owner_action(
            action,
            selected_state_id=selected_state_id,
            live_state_ids=live_state_id_tuple,
            checkpoints_by_state_id=checkpoints_by_state_id,
            checkpoint_loader=checkpoint_loader,
            solver_timeout_ms=solver_timeout_ms,
            unsat_core_timeout_ms=unsat_core_timeout_ms,
        )
    elif action.owner is EvidenceOwner.FRONTIER:
        outcome = _evaluate_frontier_owner_action(
            action,
            selected_state_id=selected_state_id,
            live_state_ids=live_state_id_tuple,
            checkpoints_by_state_id=checkpoints_by_state_id,
            checkpoint_loader=checkpoint_loader,
        )
    else:
        outcome = _inconclusive_outcome(
            action,
            explanation="shadow evaluation does not execute this owner action",
        )

    return _planned_evaluation(
        decision,
        outcome,
        selected_state_id=selected_state_id,
        live_state_ids=live_state_id_tuple,
        capsules_by_state_id=capsules_by_state_id,
    )


def evaluate_shadow_frontier(
    *,
    active_budget: BudgetVector,
    live_state_ids: Iterable[int],
    capsules_by_state_id: Mapping[int, ObligationCapsule],
    checkpoints_by_state_id: Mapping[int, FrontierCheckpoint],
    checkpoint_loader: _CheckpointLoader | None = None,
    memory_pressure: float = 0.0,
    solver_timeout_ms: int = 10000,
    unsat_core_timeout_ms: int = 5000,
) -> ShadowDecisionEvaluation:
    """Select and evaluate one live CEGIS shadow bid without mutating work."""
    live_state_id_tuple = tuple(live_state_ids)
    bids = shadow_bids_for_frontier_capsules(
        _live_capsules(
            live_state_ids=live_state_id_tuple,
            capsules_by_state_id=capsules_by_state_id,
        ),
        memory_pressure=memory_pressure,
    )
    decision = select_deterministic_bid(bids, active_budget=active_budget)
    return evaluate_shadow_decision(
        decision,
        live_state_ids=live_state_id_tuple,
        capsules_by_state_id=capsules_by_state_id,
        checkpoints_by_state_id=checkpoints_by_state_id,
        checkpoint_loader=checkpoint_loader,
        solver_timeout_ms=solver_timeout_ms,
        unsat_core_timeout_ms=unsat_core_timeout_ms,
    )


def _evaluate_solver_owner_action(
    action: EvidenceAction,
    *,
    selected_state_id: int,
    live_state_ids: tuple[int, ...],
    checkpoints_by_state_id: Mapping[int, FrontierCheckpoint],
    checkpoint_loader: _CheckpointLoader | None,
    solver_timeout_ms: int,
    unsat_core_timeout_ms: int,
) -> EvidenceOutcome:
    """Evaluate a solver-owned selected action when its checkpoint is available."""
    checkpoint = _checkpoint_for_state(
        selected_state_id,
        checkpoints_by_state_id=checkpoints_by_state_id,
        checkpoint_loader=checkpoint_loader,
    )
    if checkpoint is None:
        return _inconclusive_outcome(
            action,
            explanation="selected checkpoint is not live",
        )
    return evaluate_checkpoint_unsat_core_action(
        action,
        checkpoint,
        candidate_checkpoints=_live_checkpoints(
            live_state_ids=live_state_ids,
            checkpoints_by_state_id=checkpoints_by_state_id,
            checkpoint_loader=checkpoint_loader,
        ),
        solver_timeout_ms=solver_timeout_ms,
        unsat_core_timeout_ms=unsat_core_timeout_ms,
    )


def _evaluate_frontier_owner_action(
    action: EvidenceAction,
    *,
    selected_state_id: int,
    live_state_ids: tuple[int, ...],
    checkpoints_by_state_id: Mapping[int, FrontierCheckpoint],
    checkpoint_loader: _CheckpointLoader | None,
) -> EvidenceOutcome:
    """Evaluate a frontier-owned selected action when checkpoint evidence is available."""
    checkpoint = _checkpoint_for_state(
        selected_state_id,
        checkpoints_by_state_id=checkpoints_by_state_id,
        checkpoint_loader=checkpoint_loader,
    )
    if checkpoint is None:
        return _inconclusive_outcome(
            action,
            explanation="selected checkpoint is not live",
        )
    return evaluate_checkpoint_dominance_action(
        action,
        checkpoint,
        _live_checkpoints(
            live_state_ids=live_state_ids,
            checkpoints_by_state_id=checkpoints_by_state_id,
            checkpoint_loader=checkpoint_loader,
        ),
    )


def _planned_evaluation(
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


def _inconclusive_outcome(action: EvidenceAction, *, explanation: str) -> EvidenceOutcome:
    """Return a typed non-removing outcome for shadow-only unsupported actions."""
    return EvidenceOutcome(
        action=action,
        kind=EvidenceOutcomeKind.INCONCLUSIVE,
        explanation=explanation,
    )


def _find_live_capsule_state_id(
    capsule_id: str,
    *,
    live_state_ids: Iterable[int],
    capsules_by_state_id: Mapping[int, ObligationCapsule],
) -> int | None:
    """Return the deterministic live state ID for ``capsule_id`` when present."""
    live_ids = frozenset(live_state_ids)
    for state_id, capsule in sorted(capsules_by_state_id.items()):
        if state_id in live_ids and capsule.capsule_id == capsule_id:
            return state_id
    return None


def _live_capsules(
    *,
    live_state_ids: Iterable[int],
    capsules_by_state_id: Mapping[int, ObligationCapsule],
) -> tuple[ObligationCapsule, ...]:
    """Return live capsules in deterministic state-ID order."""
    live_ids = frozenset(live_state_ids)
    return tuple(
        capsule
        for state_id, capsule in sorted(capsules_by_state_id.items())
        if state_id in live_ids
    )


def _live_checkpoints(
    *,
    live_state_ids: Iterable[int],
    checkpoints_by_state_id: Mapping[int, FrontierCheckpoint],
    checkpoint_loader: _CheckpointLoader | None = None,
) -> tuple[FrontierCheckpoint, ...]:
    """Return live checkpoints in deterministic state-ID order."""
    live_ids = frozenset(live_state_ids)
    live_checkpoints: list[FrontierCheckpoint] = []
    for state_id in sorted(live_ids):
        checkpoint = _checkpoint_for_state(
            state_id,
            checkpoints_by_state_id=checkpoints_by_state_id,
            checkpoint_loader=checkpoint_loader,
        )
        if checkpoint is not None:
            live_checkpoints.append(checkpoint)
    return tuple(live_checkpoints)


def _checkpoint_for_state(
    state_id: int,
    *,
    checkpoints_by_state_id: Mapping[int, FrontierCheckpoint],
    checkpoint_loader: _CheckpointLoader | None,
) -> FrontierCheckpoint | None:
    """Return an existing checkpoint or lazily request one for exact owner evidence."""
    checkpoint = checkpoints_by_state_id.get(state_id)
    if checkpoint is not None or checkpoint_loader is None:
        return checkpoint
    return checkpoint_loader(state_id)
