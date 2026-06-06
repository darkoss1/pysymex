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

"""Runtime CEGIS controller for exact frontier evidence application.

The controller owns CEGIS preview/application accounting and the opt-in runtime
loop that consumes exact owner evidence. It selects proof actions through CEGIS
policy, but it does not decide solver truth or frontier materialization.
"""

from __future__ import annotations

from dataclasses import dataclass

from pysymex.execution.frontier import FrontierWorkStore
from pysymex.execution.scheduling.cegis.application import (
    EvidenceApplicationPlan,
    plan_evidence_application,
)
from pysymex.execution.scheduling.cegis.bids import shadow_bids_for_frontier_capsules
from pysymex.execution.scheduling.cegis.budgets import BudgetVector
from pysymex.execution.scheduling.cegis.evaluation import (
    ShadowDecisionEvaluation,
    evaluate_shadow_frontier,
)
from pysymex.execution.scheduling.cegis.outcomes import EvidenceOutcome

__all__ = ["CegisRuntimeController", "CegisRuntimeStats"]


@dataclass(frozen=True, slots=True)
class CegisRuntimeStats:
    """Snapshot of CEGIS preview/application telemetry."""

    enabled: bool
    bid_count: int
    evidence_preview_count: int
    evidence_preview_removable_state_count: int
    evidence_preview_invalid_count: int
    evidence_apply_count: int
    evidence_apply_removed_state_count: int
    evidence_apply_invalid_count: int
    runtime_preview_count: int
    runtime_removed_state_count: int
    runtime_nonremoving_count: int
    runtime_execution_select_count: int
    runtime_execution_no_selection_count: int

    def as_dict(self) -> dict[str, object]:
        """Return a bounded diagnostics dictionary for execution results."""
        return {
            "enabled": self.enabled,
            "bid_count": self.bid_count,
            "evidence_preview_count": self.evidence_preview_count,
            "evidence_preview_removable_state_count": (self.evidence_preview_removable_state_count),
            "evidence_preview_invalid_count": self.evidence_preview_invalid_count,
            "evidence_apply_count": self.evidence_apply_count,
            "evidence_apply_removed_state_count": self.evidence_apply_removed_state_count,
            "evidence_apply_invalid_count": self.evidence_apply_invalid_count,
            "runtime_preview_count": self.runtime_preview_count,
            "runtime_removed_state_count": self.runtime_removed_state_count,
            "runtime_nonremoving_count": self.runtime_nonremoving_count,
            "runtime_execution_select_count": self.runtime_execution_select_count,
            "runtime_execution_no_selection_count": self.runtime_execution_no_selection_count,
        }


class CegisRuntimeController:
    """Own runtime CEGIS proof-action dispatch and telemetry counters."""

    _RUNTIME_CEGIS_SOLVER_TIMEOUT_MS = 100
    _RUNTIME_CEGIS_UNSAT_CORE_TIMEOUT_MS = 100
    # Automatic proof pruning is disabled until it has issue-parity under path limits.
    _RUNTIME_CEGIS_PROOF_FRONTIER_LIMIT = 0

    def __init__(self) -> None:
        self._evidence_preview_count = 0
        self._evidence_preview_removable_state_count = 0
        self._evidence_preview_invalid_count = 0
        self._evidence_apply_count = 0
        self._evidence_apply_removed_state_count = 0
        self._evidence_apply_invalid_count = 0
        self._runtime_preview_count = 0
        self._runtime_removed_state_count = 0
        self._runtime_nonremoving_count = 0
        self._runtime_execution_select_count = 0
        self._runtime_execution_no_selection_count = 0
        self._detector_selection_frontier_id: int | None = None
        self._detector_selection_frontier_version = -1
        self._detector_selection_state_id: int | None = None

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

    def apply_runtime_evidence(self, frontier: FrontierWorkStore) -> None:
        """Consume exact CEGIS owner evidence when an automatic proof budget is active."""
        if len(frontier) > self._RUNTIME_CEGIS_PROOF_FRONTIER_LIMIT:
            return
        remaining_attempts = len(frontier)
        while len(frontier) > 0 and remaining_attempts > 0:
            evaluation = self.preview_shadow_frontier(
                frontier,
                self._runtime_budget(frontier),
                solver_timeout_ms=self._RUNTIME_CEGIS_SOLVER_TIMEOUT_MS,
                unsat_core_timeout_ms=self._RUNTIME_CEGIS_UNSAT_CORE_TIMEOUT_MS,
            )
            self._runtime_preview_count += 1
            outcome = evaluation.outcome
            if outcome is None or not evaluation.can_remove:
                self._runtime_nonremoving_count += 1
                return

            removed_count = self.apply_evidence_outcome(frontier, outcome)
            if removed_count <= 0:
                self._runtime_nonremoving_count += 1
                return

            self._runtime_removed_state_count += removed_count
            remaining_attempts -= removed_count

    def select_runtime_execution_state_id(self, frontier: FrontierWorkStore) -> int | None:
        """Select a detector-obligation state through resident CEGIS telemetry."""
        state_id = self._select_detector_execution_state_id(frontier)
        if state_id is None:
            self._runtime_execution_no_selection_count += 1
            return None

        self._runtime_execution_select_count += 1
        return state_id

    def preview_evidence_outcome(
        self,
        frontier: FrontierWorkStore,
        outcome: EvidenceOutcome,
    ) -> EvidenceApplicationPlan:
        """Plan CEGIS owner outcome application without mutating the frontier."""
        plan = self._plan_evidence_outcome(frontier, outcome)
        self._evidence_preview_count += 1
        self._record_evidence_preview(plan)
        return plan

    def apply_evidence_outcome(
        self,
        frontier: FrontierWorkStore,
        outcome: EvidenceOutcome,
    ) -> int:
        """Remove queued states covered by a valid CEGIS owner outcome."""
        plan = self._plan_evidence_outcome(frontier, outcome)
        self._evidence_apply_count += 1
        if plan.invalid_removal_attempt:
            self._evidence_apply_invalid_count += 1
        if not plan.can_remove:
            return 0

        for state_id in plan.removable_state_ids:
            frontier.discard(state_id)

        removed_state_count = len(plan.removable_state_ids)
        self._evidence_apply_removed_state_count += removed_state_count
        return removed_state_count

    def collect_stats(self, frontier: FrontierWorkStore, *, enabled: bool) -> CegisRuntimeStats:
        """Return bounded CEGIS diagnostics for live frontier work."""
        return CegisRuntimeStats(
            enabled=enabled,
            bid_count=self._bid_count(frontier) if enabled else 0,
            evidence_preview_count=self._evidence_preview_count,
            evidence_preview_removable_state_count=self._evidence_preview_removable_state_count,
            evidence_preview_invalid_count=self._evidence_preview_invalid_count,
            evidence_apply_count=self._evidence_apply_count,
            evidence_apply_removed_state_count=self._evidence_apply_removed_state_count,
            evidence_apply_invalid_count=self._evidence_apply_invalid_count,
            runtime_preview_count=self._runtime_preview_count,
            runtime_removed_state_count=self._runtime_removed_state_count,
            runtime_nonremoving_count=self._runtime_nonremoving_count,
            runtime_execution_select_count=self._runtime_execution_select_count,
            runtime_execution_no_selection_count=self._runtime_execution_no_selection_count,
        )

    def _runtime_budget(self, frontier: FrontierWorkStore) -> BudgetVector:
        """Return the per-dispatch runtime CEGIS budget for exact proof actions."""
        return BudgetVector(
            wall_time_ms=10.0,
            solver_time_ms=10.0,
            resident_units=max(1, len(frontier.capsules) * 128),
            reconstruction_units=max(1, len(frontier.checkpoints) * 128),
            path_budget=max(1, len(frontier)),
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

    def _record_evidence_preview(self, plan: EvidenceApplicationPlan) -> None:
        """Update telemetry for a non-mutating CEGIS evidence preview."""
        if plan.invalid_removal_attempt:
            self._evidence_preview_invalid_count += 1
        if plan.can_remove:
            self._evidence_preview_removable_state_count += len(plan.removable_state_ids)

    def _bid_count(self, frontier: FrontierWorkStore) -> int:
        """Return the current number of live frontier CEGIS bids."""
        return len(shadow_bids_for_frontier_capsules(frontier.capsules.values()))

    def _select_detector_execution_state_id(self, frontier: FrontierWorkStore) -> int | None:
        """Return the best live detector-obligation state for immediate execution."""
        frontier_id = id(frontier)
        frontier_version = frontier.selection_version
        if (
            self._detector_selection_frontier_id == frontier_id
            and self._detector_selection_frontier_version == frontier_version
        ):
            selected_state_id = self._detector_selection_state_id
            if selected_state_id is None or selected_state_id in frontier:
                return selected_state_id

        selected: tuple[int, int, str, int] | None = None
        for state_id, features in frontier.runtime_features.items():
            if state_id not in frontier:
                continue
            detector_count = features.detector_obligation_count
            if detector_count <= 0:
                continue
            candidate = (
                -detector_count,
                features.estimated_resident_units,
                features.capsule_id,
                state_id,
            )
            if selected is None or candidate < selected:
                selected = candidate
        if selected is not None:
            selected_state_id = selected[3]
            self._cache_detector_selection(frontier_id, frontier_version, selected_state_id)
            return selected_state_id

        for state_id, capsule in frontier.capsules.items():
            if state_id not in frontier:
                continue
            detector_count = capsule.footprint.detector_obligation_count
            if detector_count <= 0:
                continue
            candidate = (
                -detector_count,
                capsule.estimated_resident_units,
                capsule.capsule_id,
                state_id,
            )
            if selected is None or candidate < selected:
                selected = candidate
        if selected is None:
            self._cache_detector_selection(frontier_id, frontier_version, None)
            return None
        selected_state_id = selected[3]
        self._cache_detector_selection(frontier_id, frontier_version, selected_state_id)
        return selected_state_id

    def _cache_detector_selection(
        self,
        frontier_id: int,
        frontier_version: int,
        state_id: int | None,
    ) -> None:
        """Remember detector-state selection for unchanged frontier inputs."""
        self._detector_selection_frontier_id = frontier_id
        self._detector_selection_frontier_version = frontier_version
        self._detector_selection_state_id = state_id
