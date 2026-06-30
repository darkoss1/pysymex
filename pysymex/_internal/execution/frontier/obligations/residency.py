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

"""Resident-unit and havoc-root estimates for frontier obligation capsules."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.frontier.evidence import havoc_root_count

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState


def estimate_resident_units(state: VMState) -> int:
    """Return a deterministic size proxy for migration telemetry."""
    return (
        len(state.stack)
        + len(state.local_vars)
        + len(state.global_vars)
        + len(state.memory)
        + len(state.path_constraints)
        + len(state.branch_trace)
        + len(state.deferred_detector_issues)
        + len(state.write_events)
    )


def state_havoc_live_count(state: VMState) -> int:
    """Return top-level havoc roots visible to frontier telemetry."""
    return havoc_root_count(
        (
            *state.stack,
            *state.local_vars.values(),
            *state.global_vars.values(),
            *state.memory.values(),
            *((state.active_exception,) if state.active_exception is not None else ()),
            *(
                (state.pending_reraise_exception,)
                if state.pending_reraise_exception is not None
                else ()
            ),
            *state.awaitable_results.values(),
        ),
    )
