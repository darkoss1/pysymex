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

"""Shadow CEGIS owner evaluators."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.solver.engine.incremental import IncrementalSolver
from pysymex._internal.core.solver.unsat import extract_unsat_core
from pysymex._internal.execution.frontier.proof.index import exact_unsat_core_coverage
from pysymex._internal.execution.scheduling.cegis.bids.types import (
    EvidenceAction,
    EvidenceActionKind,
    EvidenceOwner,
)
from pysymex._internal.execution.scheduling.cegis.outcomes.dominance import (
    dominance_certificate_outcome,
)
from pysymex._internal.execution.scheduling.cegis.outcomes.solver import solver_unsat_core_outcome
from pysymex._internal.execution.scheduling.cegis.outcomes.types import (
    EvidenceOutcome,
    EvidenceOutcomeKind,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from pysymex._internal.execution.frontier.checkpoints import FrontierCheckpoint


def choose_checkpoint_dominance_action(
    action: EvidenceAction,
    subject: FrontierCheckpoint,
    candidates: Iterable[FrontierCheckpoint],
) -> EvidenceOutcome:
    """Evaluate exact duplicate dominance for live checkpoints."""
    if (
        action.kind is not EvidenceActionKind.CHECK_DOMINANCE
        or action.owner is not EvidenceOwner.FRONTIER
    ):
        return EvidenceOutcome(
            action=action,
            kind=EvidenceOutcomeKind.INCONCLUSIVE,
            explanation="action is not a frontier-owned dominance action",
        )
    if action.capsule_id != subject.capsule.capsule_id:
        return EvidenceOutcome(
            action=action,
            kind=EvidenceOutcomeKind.INCONCLUSIVE,
            explanation="action capsule does not match dominance subject",
        )

    dominated_capsule_ids = tuple(
        candidate.capsule.capsule_id
        for candidate in candidates
        if candidate.capsule.capsule_id != subject.capsule.capsule_id
        and subject.structurally_matches(candidate)
    )
    return dominance_certificate_outcome(action, dominated_capsule_ids=dominated_capsule_ids)


def choose_checkpoint_unsat_core_action(
    action: EvidenceAction,
    checkpoint: FrontierCheckpoint,
    *,
    candidate_checkpoints: Iterable[FrontierCheckpoint] | None = None,
    solver_timeout_ms: int = 10000,
    unsat_core_timeout_ms: int = 5000,
) -> EvidenceOutcome:
    """Evaluate a solver-owned UNSAT-core action against a reconstructed checkpoint."""
    if (
        action.kind is not EvidenceActionKind.TRY_UNSAT_CORE
        or action.owner is not EvidenceOwner.SOLVER
    ):
        return EvidenceOutcome(
            action=action,
            kind=EvidenceOutcomeKind.INCONCLUSIVE,
            explanation="action is not a solver-owned UNSAT-core action",
        )
    if action.capsule_id != checkpoint.capsule.capsule_id:
        return EvidenceOutcome(
            action=action,
            kind=EvidenceOutcomeKind.INCONCLUSIVE,
            explanation="action capsule does not match checkpoint capsule",
        )

    reconstruction = checkpoint.reconstruct()
    if not reconstruction.is_exact or reconstruction.reconstructed_state is None:
        return EvidenceOutcome(
            action=action,
            kind=EvidenceOutcomeKind.INCONCLUSIVE,
            explanation=f"checkpoint reconstruction is {reconstruction.status.value}",
        )

    constraints = reconstruction.reconstructed_state.path_constraints.to_list()
    solver_result = IncrementalSolver(
        timeout_ms=solver_timeout_ms,
        use_cache=False,
    ).check_sat_result(constraints)
    core_result = (
        extract_unsat_core(constraints, timeout_ms=unsat_core_timeout_ms)
        if solver_result.is_unsat
        else None
    )
    core_indices = tuple(core_result.core_indices) if core_result is not None else ()
    coverage = exact_unsat_core_coverage(
        checkpoint,
        candidate_checkpoints if candidate_checkpoints is not None else (checkpoint,),
        core_indices=core_indices,
    )
    return solver_unsat_core_outcome(
        action,
        solver_result,
        covered_capsule_ids=coverage.covered_capsule_ids,
        core_indices=core_indices,
    )
