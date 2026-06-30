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

"""CEGIS integration helpers for POLAR path managers."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.frontier.modes import FrontierRuntimeMode
    from pysymex._internal.execution.frontier.store.core import FrontierWorkStore
    from pysymex._internal.execution.scheduling.cegis.application import EvidenceApplicationPlan
    from pysymex._internal.execution.scheduling.cegis.budgets import BudgetVector
    from pysymex._internal.execution.scheduling.cegis.evaluation.types import (
        ShadowDecisionEvaluation,
    )
    from pysymex._internal.execution.scheduling.cegis.outcomes.types import EvidenceOutcome
    from pysymex._internal.execution.scheduling.cegis.runtime.controller import (
        CegisRuntimeController,
    )
    from pysymex._internal.execution.scheduling.telemetry import SchedulerDecisionSource


class PolarCegisManagerMixin:
    """Manager methods that bridge POLAR frontier storage with CEGIS evidence."""

    if TYPE_CHECKING:
        _frontier: FrontierWorkStore
        _frontier_runtime_mode: FrontierRuntimeMode
        _cegis_runtime: CegisRuntimeController

        def _pop_state_with_scheduler_event(
            self,
            state_id: int,
            *,
            decision_source: SchedulerDecisionSource,
            priority: float | None,
            path_decision: str,
            reason: str,
        ) -> VMState | None: ...

    def preview_shadow_cegis_frontier(
        self,
        active_budget: BudgetVector,
        *,
        memory_pressure: float = 0.0,
        solver_timeout_ms: int = 10000,
        unsat_core_timeout_ms: int = 5000,
    ) -> ShadowDecisionEvaluation:
        """Select and evaluate one live CEGIS shadow bid without mutating work."""
        return self._cegis_runtime.preview_shadow_frontier(
            self._frontier,
            active_budget,
            memory_pressure=memory_pressure,
            solver_timeout_ms=solver_timeout_ms,
            unsat_core_timeout_ms=unsat_core_timeout_ms,
        )

    def preview_evidence_outcome(self, outcome: EvidenceOutcome) -> EvidenceApplicationPlan:
        """Plan CEGIS owner outcome application without mutating the frontier."""
        return self._cegis_runtime.preview_evidence_outcome(self._frontier, outcome)

    def apply_evidence_outcome(self, outcome: EvidenceOutcome) -> int:
        """Remove queued states covered by a valid CEGIS owner outcome."""
        return self._cegis_runtime.apply_evidence_outcome(self._frontier, outcome)

    def _pop_runtime_cegis_state(self) -> VMState | None:
        """Pop the next runtime state selected by deterministic CEGIS execute bids."""
        state_id = self._cegis_runtime.select_runtime_execution_state_id(self._frontier)
        if state_id is None:
            return None
        return self._pop_state_with_scheduler_event(
            state_id,
            decision_source="cegis_execute",
            priority=None,
            path_decision="cegis-execute",
            reason="detector-obligation state selected by CEGIS runtime",
        )
