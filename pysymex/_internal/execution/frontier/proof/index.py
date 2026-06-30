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

"""Exact proof-coverage helpers for POLAR frontier checkpoints.

Proof reuse is owned by the frontier/proof layer, not by the scheduler. The
helpers here only widen UNSAT-core coverage when a live checkpoint contains the
same exact Z3 constraint ASTs that formed a solver-owned core.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import z3

if TYPE_CHECKING:
    from collections.abc import Iterable

    from pysymex._internal.execution.frontier.checkpoints import FrontierCheckpoint


@dataclass(frozen=True, slots=True)
class UnsatCoreCoverage:
    """Exact live-capsule coverage for one solver-owned UNSAT core."""

    subject_capsule_id: str
    covered_capsule_ids: tuple[str, ...]
    core_indices: tuple[int, ...]
    core_constraint_count: int


def exact_unsat_core_coverage(
    subject: FrontierCheckpoint,
    candidates: Iterable[FrontierCheckpoint],
    *,
    core_indices: tuple[int, ...],
) -> UnsatCoreCoverage:
    """Return live checkpoints that contain every exact core constraint.

    The selected solver action proves UNSAT for ``subject``. A candidate is
    covered only when its checkpoint is still digest-exact and its path
    constraints contain all selected core constraints by Z3 AST identity.
    """
    subject_constraints = subject.path_constraints()
    core_constraints = _core_constraints(subject_constraints, core_indices)
    if len(core_constraints) != len(core_indices) or not core_constraints:
        return UnsatCoreCoverage(
            subject_capsule_id=subject.capsule.capsule_id,
            covered_capsule_ids=(),
            core_indices=core_indices,
            core_constraint_count=len(core_constraints),
        )

    covered_capsule_ids = tuple(
        candidate.capsule.capsule_id
        for candidate in sorted(candidates, key=lambda item: item.capsule.capsule_id)
        if candidate.snapshot_matches_capsule()
        and _constraints_cover_core(candidate.path_constraints(), core_constraints)
    )
    return UnsatCoreCoverage(
        subject_capsule_id=subject.capsule.capsule_id,
        covered_capsule_ids=covered_capsule_ids,
        core_indices=core_indices,
        core_constraint_count=len(core_constraints),
    )


def _core_constraints(
    constraints: tuple[z3.BoolRef, ...],
    core_indices: tuple[int, ...],
) -> tuple[z3.BoolRef, ...]:
    """Return exact constraints addressed by ``core_indices`` when valid."""
    core_constraints: list[z3.BoolRef] = []
    for index in core_indices:
        if index < 0 or index >= len(constraints):
            return ()
        core_constraints.append(constraints[index])
    return tuple(core_constraints)


def _constraints_cover_core(
    candidate_constraints: tuple[z3.BoolRef, ...],
    core_constraints: tuple[z3.BoolRef, ...],
) -> bool:
    """Return whether ``candidate_constraints`` contain all exact core ASTs."""
    return all(
        any(
            z3.eq(candidate_constraint, core_constraint)
            for candidate_constraint in candidate_constraints
        )
        for core_constraint in core_constraints
    )
