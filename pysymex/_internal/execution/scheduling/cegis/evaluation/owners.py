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

"""Owner-specific CEGIS shadow action evaluation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.scheduling.cegis.evaluation.live import (
    CheckpointLoader,
    checkpoint_for_state,
    live_checkpoints,
)
from pysymex._internal.execution.scheduling.cegis.owners import (
    choose_checkpoint_dominance_action,
    choose_checkpoint_unsat_core_action,
)

from .planning import inconclusive_outcome

if TYPE_CHECKING:
    from collections.abc import Mapping

    from pysymex._internal.execution.frontier.checkpoints import FrontierCheckpoint
    from pysymex._internal.execution.scheduling.cegis.bids.types import EvidenceAction
    from pysymex._internal.execution.scheduling.cegis.outcomes.types import EvidenceOutcome


def choose_solver_owner_action(
    action: EvidenceAction,
    *,
    selected_state_id: int,
    live_state_ids: tuple[int, ...],
    checkpoints_by_state_id: Mapping[int, FrontierCheckpoint],
    checkpoint_loader: CheckpointLoader | None,
    solver_timeout_ms: int,
    unsat_core_timeout_ms: int,
) -> EvidenceOutcome:
    """Evaluate a solver-owned selected action when its checkpoint is available."""
    checkpoint = checkpoint_for_state(
        selected_state_id,
        checkpoints_by_state_id=checkpoints_by_state_id,
        checkpoint_loader=checkpoint_loader,
    )
    if checkpoint is None:
        return inconclusive_outcome(
            action,
            explanation="selected checkpoint is not live",
        )
    return choose_checkpoint_unsat_core_action(
        action,
        checkpoint,
        candidate_checkpoints=live_checkpoints(
            live_state_ids=live_state_ids,
            checkpoints_by_state_id=checkpoints_by_state_id,
            checkpoint_loader=checkpoint_loader,
        ),
        solver_timeout_ms=solver_timeout_ms,
        unsat_core_timeout_ms=unsat_core_timeout_ms,
    )


def choose_frontier_owner_action(
    action: EvidenceAction,
    *,
    selected_state_id: int,
    live_state_ids: tuple[int, ...],
    checkpoints_by_state_id: Mapping[int, FrontierCheckpoint],
    checkpoint_loader: CheckpointLoader | None,
) -> EvidenceOutcome:
    """Evaluate a frontier-owned selected action when checkpoint evidence is available."""
    checkpoint = checkpoint_for_state(
        selected_state_id,
        checkpoints_by_state_id=checkpoints_by_state_id,
        checkpoint_loader=checkpoint_loader,
    )
    if checkpoint is None:
        return inconclusive_outcome(
            action,
            explanation="selected checkpoint is not live",
        )
    return choose_checkpoint_dominance_action(
        action,
        checkpoint,
        live_checkpoints(
            live_state_ids=live_state_ids,
            checkpoints_by_state_id=checkpoints_by_state_id,
            checkpoint_loader=checkpoint_loader,
        ),
    )
