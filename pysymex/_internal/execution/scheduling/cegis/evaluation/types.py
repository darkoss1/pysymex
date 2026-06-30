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

"""Result types for non-mutating CEGIS shadow evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex._internal.execution.scheduling.cegis.application import EvidenceApplicationPlan
    from pysymex._internal.execution.scheduling.cegis.outcomes.types import EvidenceOutcome
    from pysymex._internal.execution.scheduling.cegis.policy import SchedulerDecision


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
