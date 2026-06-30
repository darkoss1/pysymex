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

"""State transitions for execution path-feasibility outcomes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.feasibility.events import (
    HookMap,
    publish_prune_hooks,
    record_solver_unknown_path_feasibility,
)
from pysymex._internal.execution.feasibility.persistence import persist_verified_constraint_suffix

if TYPE_CHECKING:
    import z3

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.session.state.core import ExecutionSession
    from pysymex._internal.typing.protocols import SolverProtocol


def record_infeasible_path(
    *,
    session: ExecutionSession,
    hook_owner: object,
    hooks: HookMap,
    state: VMState,
) -> None:
    """Record a path pruned only after feasibility policy proves it infeasible."""
    session.paths_pruned += 1
    publish_prune_hooks(hook_owner=hook_owner, hooks=hooks, state=state)


def record_inconclusive_path(
    *,
    session: ExecutionSession,
    state: VMState,
    reason: str,
) -> None:
    """Record inconclusive feasibility without pruning or clearing pending constraints."""
    record_solver_unknown_path_feasibility(
        session=session,
        state=state,
        reason=reason,
    )
    state.last_inconclusive_feasibility_len = len(state.path_constraints)


def record_feasible_path(
    *,
    solver: SolverProtocol,
    constraints: list[z3.BoolRef],
    known_prefix_len: int,
    state: VMState,
) -> None:
    """Persist verified constraints and clear pending feasibility state."""
    persist_verified_constraint_suffix(
        solver=solver,
        constraints=constraints,
        known_prefix_len=known_prefix_len,
    )
    state.pending_constraint_count = 0
    state.last_inconclusive_feasibility_len = -1
