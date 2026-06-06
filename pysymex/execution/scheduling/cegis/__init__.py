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

"""CEGIS scheduler shadow types.

The Costed Evidence-Guided Indexed Scheduler is introduced in shadow form
first. Runtime replacement consumes only exact owner certificates through the
path-manager application gate.
"""

from __future__ import annotations

from pysymex.execution.scheduling.cegis.application import (
    EvidenceApplicationPlan,
    plan_evidence_application,
)
from pysymex.execution.scheduling.cegis.bids import (
    EvidenceAction,
    EvidenceActionKind,
    EvidenceBid,
    EvidenceOwner,
    shadow_bids_for_capsule,
    shadow_bids_for_frontier_capsules,
)
from pysymex.execution.scheduling.cegis.budgets import BudgetVector
from pysymex.execution.scheduling.cegis.evaluation import (
    ShadowDecisionEvaluation,
    evaluate_shadow_decision,
    evaluate_shadow_frontier,
)
from pysymex.execution.scheduling.cegis.features import (
    SchedulingFeatureVector,
    feature_vector_from_capsule,
)
from pysymex.execution.scheduling.cegis.outcomes import (
    EvidenceCertificate,
    EvidenceCertificateKind,
    EvidenceOutcome,
    EvidenceOutcomeKind,
    dominance_certificate_outcome,
    solver_unsat_core_outcome,
)
from pysymex.execution.scheduling.cegis.owners import (
    evaluate_capsule_dominance_action,
    evaluate_checkpoint_dominance_action,
    evaluate_checkpoint_unsat_core_action,
)
from pysymex.execution.scheduling.cegis.policy import (
    SchedulerDecision,
    select_deterministic_bid,
)
from pysymex.execution.scheduling.cegis.runtime import (
    CegisRuntimeController,
    CegisRuntimeStats,
)

__all__ = [
    "CegisRuntimeController",
    "CegisRuntimeStats",
    "BudgetVector",
    "EvidenceAction",
    "EvidenceApplicationPlan",
    "EvidenceActionKind",
    "EvidenceBid",
    "EvidenceCertificate",
    "EvidenceCertificateKind",
    "EvidenceOwner",
    "EvidenceOutcome",
    "EvidenceOutcomeKind",
    "SchedulerDecision",
    "SchedulingFeatureVector",
    "ShadowDecisionEvaluation",
    "dominance_certificate_outcome",
    "evaluate_capsule_dominance_action",
    "evaluate_checkpoint_dominance_action",
    "evaluate_checkpoint_unsat_core_action",
    "evaluate_shadow_decision",
    "evaluate_shadow_frontier",
    "feature_vector_from_capsule",
    "plan_evidence_application",
    "select_deterministic_bid",
    "shadow_bids_for_capsule",
    "shadow_bids_for_frontier_capsules",
    "solver_unsat_core_outcome",
]
