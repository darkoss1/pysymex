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

"""Live-frontier CEGIS shadow bid selection and evaluation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.scheduling.cegis.bids.frontier import (
    shadow_bids_for_frontier_capsules,
)
from pysymex._internal.execution.scheduling.cegis.evaluation.live import (
    CheckpointLoader,
    live_capsules,
)
from pysymex._internal.execution.scheduling.cegis.policy import select_deterministic_bid

from .decision import evaluate_shadow_decision

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from pysymex._internal.execution.frontier.checkpoints import FrontierCheckpoint
    from pysymex._internal.execution.frontier.obligations.types import ObligationCapsule
    from pysymex._internal.execution.scheduling.cegis.budgets import BudgetVector

    from .types import ShadowDecisionEvaluation


def evaluate_shadow_frontier(
    *,
    active_budget: BudgetVector,
    live_state_ids: Iterable[int],
    capsules_by_state_id: Mapping[int, ObligationCapsule],
    checkpoints_by_state_id: Mapping[int, FrontierCheckpoint],
    checkpoint_loader: CheckpointLoader | None = None,
    memory_pressure: float = 0.0,
    solver_timeout_ms: int = 10000,
    unsat_core_timeout_ms: int = 5000,
) -> ShadowDecisionEvaluation:
    """Select and evaluate one live CEGIS shadow bid without mutating work."""
    live_state_id_tuple = tuple(live_state_ids)
    bids = shadow_bids_for_frontier_capsules(
        live_capsules(
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
