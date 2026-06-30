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

"""Build shadow POLAR capsules from live VM states."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.frontier.evidence import detector_obligation_digest
from pysymex._internal.execution.frontier.obligations.digests import state_structural_hash
from pysymex._internal.execution.frontier.obligations.residency import (
    estimate_resident_units,
    state_havoc_live_count,
)
from pysymex._internal.execution.frontier.obligations.types import (
    LiveSemanticFootprint,
    ObligationCapsule,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState


def build_shadow_capsule(
    state: VMState,
    *,
    capsule_id: str | None = None,
    parent_id: str | None = None,
) -> ObligationCapsule:
    """Build a conservative POLAR shadow capsule from ``state``.

    The function reads VMState metadata only. It does not run the solver,
    change execution-visible state, or classify path feasibility.
    """
    constraint_atom_ids = state.path_constraints.sorted_constraint_hashes()
    branch_trace_length = len(state.branch_trace)
    footprint = LiveSemanticFootprint(
        pc=state.pc,
        state_structural_hash=state_structural_hash(state),
        stack_depth=len(state.stack),
        local_names=state.local_vars.sorted_keys(),
        global_names=state.global_vars.sorted_keys(),
        memory_cell_count=len(state.memory),
        active_exception=state.active_exception is not None,
        pending_reraise_exception=state.pending_reraise_exception is not None,
        write_event_count=len(state.write_events),
        detector_obligation_count=len(state.deferred_detector_issues),
        detector_obligation_keys=detector_obligation_digest(
            tuple(state.deferred_detector_issues),
        ),
        havoc_live_count=state_havoc_live_count(state),
    )
    stable_id = capsule_id
    if stable_id is None:
        stable_id = (
            f"capsule:{state.path_id}:{state.pc}:{state.depth}:"
            f"{len(constraint_atom_ids)}:{branch_trace_length}"
        )

    return ObligationCapsule(
        capsule_id=stable_id,
        parent_id=parent_id,
        path_id=state.path_id,
        depth=state.depth,
        footprint=footprint,
        constraint_atom_ids=constraint_atom_ids,
        pending_constraint_count=state.pending_constraint_count,
        branch_trace_length=branch_trace_length,
        estimated_resident_units=estimate_resident_units(state),
    )
