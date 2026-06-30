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

"""Runtime CEGIS evidence dispatch.

The controller owns explicit CEGIS preview/application dispatch and detector
obligation state selection. It does not decide solver truth, frontier
materialization, or the shape of telemetry snapshots.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.scheduling.cegis.application import (
    EvidenceApplicationPlan,
    plan_evidence_application,
)
from pysymex._internal.execution.scheduling.cegis.bids.frontier import (
    shadow_bids_for_frontier_capsules,
)
from pysymex._internal.execution.scheduling.cegis.budgets import BudgetVector
from pysymex._internal.execution.scheduling.cegis.evaluation.frontier import (
    evaluate_shadow_frontier,
)
from pysymex._internal.execution.scheduling.cegis.runtime.accounting import CegisRuntimeAccounting
from pysymex._internal.execution.scheduling.cegis.runtime.selection import (
    DetectorExecutionSelectionCache,
)

if TYPE_CHECKING:
    from pysymex._internal.execution.frontier.store.core import FrontierWorkStore
    from pysymex._internal.execution.scheduling.cegis.evaluation.types import (
        ShadowDecisionEvaluation,
    )
    from pysymex._internal.execution.scheduling.cegis.outcomes.types import EvidenceOutcome
    from pysymex._internal.execution.scheduling.cegis.runtime.stats import CegisRuntimeStats


class CegisRuntimeController:
    """Own runtime CEGIS proof-action dispatch."""

    def __init__(self) -> None:
        self._accounting = CegisRuntimeAccounting()
        self._detector_selection = DetectorExecutionSelectionCache()

    def preview_shadow_frontier(
        self,
        frontier: FrontierWorkStore,
        active_budget: BudgetVector,
        *,
        memory_pressure: float = 0.0,
        solver_timeout_ms: int = 10000,
        unsat_core_timeout_ms: int = 5000,
    ) -> ShadowDecisionEvaluation:
        """Select and evaluate one live CEGIS shadow bid without mutating work."""
        frontier.ensure_capsules_for_live_states()
        return evaluate_shadow_frontier(
            active_budget=active_budget,
            live_state_ids=frontier.live_state_ids,
            capsules_by_state_id=frontier.capsules,
            checkpoints_by_state_id=frontier.checkpoints,
            checkpoint_loader=frontier.ensure_checkpoint,
            memory_pressure=memory_pressure,
            solver_timeout_ms=solver_timeout_ms,
            unsat_core_timeout_ms=unsat_core_timeout_ms,
        )

    def select_runtime_execution_state_id(self, frontier: FrontierWorkStore) -> int | None:
        """Select a detector-obligation state through resident CEGIS telemetry."""
        state_id = self._detector_selection.select(frontier)
        self._accounting.record_runtime_execution_selection(state_id is not None)
        return state_id

    def preview_evidence_outcome(
        self,
        frontier: FrontierWorkStore,
        outcome: EvidenceOutcome,
    ) -> EvidenceApplicationPlan:
        """Plan CEGIS owner outcome application without mutating the frontier."""
        plan = self._plan_evidence_outcome(frontier, outcome)
        self._accounting.record_evidence_preview(plan)
        return plan

    def apply_evidence_outcome(
        self,
        frontier: FrontierWorkStore,
        outcome: EvidenceOutcome,
    ) -> int:
        """Remove queued states covered by a valid CEGIS owner outcome."""
        plan = self._plan_evidence_outcome(frontier, outcome)
        if not plan.can_remove:
            self._accounting.record_evidence_apply(plan, removed_state_count=0)
            return 0

        for state_id in plan.removable_state_ids:
            frontier.discard(state_id)

        removed_state_count = len(plan.removable_state_ids)
        self._accounting.record_evidence_apply(
            plan,
            removed_state_count=removed_state_count,
        )
        return removed_state_count

    def collect_stats(self, frontier: FrontierWorkStore, *, enabled: bool) -> CegisRuntimeStats:
        """Return bounded CEGIS diagnostics for live frontier work."""
        return self._accounting.collect_stats(
            enabled=enabled,
            bid_count=self._bid_count(frontier) if enabled else 0,
        )

    def _plan_evidence_outcome(
        self,
        frontier: FrontierWorkStore,
        outcome: EvidenceOutcome,
    ) -> EvidenceApplicationPlan:
        """Build the shared no-false-prune plan for preview and application."""
        frontier.ensure_capsules_for_live_states()
        return plan_evidence_application(
            outcome,
            live_state_ids=frontier.live_state_ids,
            capsules_by_state_id=frontier.capsules,
        )

    def _bid_count(self, frontier: FrontierWorkStore) -> int:
        """Return the current number of live frontier CEGIS bids."""
        return len(shadow_bids_for_frontier_capsules(frontier.capsules.values()))
