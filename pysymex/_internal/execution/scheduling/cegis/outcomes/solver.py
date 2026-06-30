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

"""Solver-owned CEGIS outcomes for UNSAT-core evidence."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.scheduling.cegis.bids.types import (
    EvidenceAction,
    EvidenceActionKind,
)
from pysymex._internal.execution.scheduling.cegis.outcomes.types import (
    EvidenceCertificate,
    EvidenceCertificateKind,
    EvidenceOutcome,
    EvidenceOutcomeKind,
)

if TYPE_CHECKING:
    from pysymex._internal.core.solver.engine.results import SolverResult


def solver_unsat_core_outcome(
    action: EvidenceAction,
    solver_result: SolverResult,
    *,
    covered_capsule_ids: tuple[str, ...],
    core_indices: tuple[int, ...],
    timed_out: bool = False,
) -> EvidenceOutcome:
    """Build a CEGIS outcome from solver-owned UNSAT-core evidence.

    SAT, UNKNOWN, timeout, malformed action, and missing-core cases are
    explicitly non-removing. Only structured UNSAT with at least one core index
    can produce an ``UNSAT_CORE`` certificate.
    """
    if action.kind is not EvidenceActionKind.TRY_UNSAT_CORE:
        return EvidenceOutcome(
            action=action,
            kind=EvidenceOutcomeKind.INCONCLUSIVE,
            explanation="action is not an UNSAT-core solver action",
        )
    if solver_result.is_sat:
        return EvidenceOutcome(
            action=action,
            kind=EvidenceOutcomeKind.SAT,
            explanation="solver established SAT; no UNSAT removal certificate",
        )
    if solver_result.is_unknown:
        return EvidenceOutcome(
            action=action,
            kind=EvidenceOutcomeKind.TIMEOUT if timed_out else EvidenceOutcomeKind.SOLVER_UNKNOWN,
            explanation="solver result is inconclusive",
        )
    if not solver_result.is_unsat:
        return EvidenceOutcome(
            action=action,
            kind=EvidenceOutcomeKind.INCONCLUSIVE,
            explanation="solver did not establish exact UNSAT",
        )
    if not core_indices:
        return EvidenceOutcome(
            action=action,
            kind=EvidenceOutcomeKind.INCONCLUSIVE,
            explanation="solver established UNSAT but no core certificate was supplied",
        )
    if action.capsule_id not in covered_capsule_ids:
        return EvidenceOutcome(
            action=action,
            kind=EvidenceOutcomeKind.INCONCLUSIVE,
            explanation="UNSAT-core certificate did not cover the selected capsule",
        )
    certificate = EvidenceCertificate(
        kind=EvidenceCertificateKind.UNSAT_CORE,
        subject_capsule_id=action.capsule_id,
        covered_capsule_ids=covered_capsule_ids,
        core_indices=core_indices,
        explanation="solver-owned UNSAT core evidence",
    )
    return EvidenceOutcome(
        action=action,
        kind=EvidenceOutcomeKind.EXACT_UNSAT,
        removed_capsule_ids=covered_capsule_ids,
        certificate=certificate,
        explanation="solver established exact UNSAT core coverage",
    )
