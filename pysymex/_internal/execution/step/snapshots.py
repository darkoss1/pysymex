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

"""Path and dispatch snapshot helpers for one-instruction execution steps."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.session.state.core import ExecutionSession
    from pysymex._internal.execution.step.types import StackValueItems


def snapshot_stack_mapping(values: StackValueItems) -> dict[str, object]:
    """Shallow-copy a name-to-stack-value mapping for path snapshots."""
    return dict(values.items())


def snapshot_objects(values: Iterable[object]) -> list[object]:
    """Materialize an iterable snapshot used when recording path stacks."""
    return list(values)


def record_dispatch_snapshots(*, session: ExecutionSession, state: VMState) -> None:
    """Record globals, locals, and stack snapshots after opcode dispatch."""
    if state.call_stack:
        session.last_locals = snapshot_stack_mapping(state.call_stack[-1].local_vars)
    else:
        session.last_locals = snapshot_stack_mapping(state.local_vars)
    session.last_globals = snapshot_stack_mapping(state.global_vars)
    session.last_stack = snapshot_objects(state.stack)


def record_terminal_path(
    *,
    session: ExecutionSession,
    state: VMState,
    include_stack: bool,
    final_exception: object | None = None,
    update_exception: bool = False,
) -> None:
    """Record counters and snapshots for a terminal path."""
    session.paths_completed += 1
    session.last_branches = state.branch_trace.to_list()
    session.last_globals = snapshot_stack_mapping(state.global_vars)
    session.last_locals = snapshot_stack_mapping(state.local_vars)
    if include_stack:
        session.last_stack = snapshot_objects(state.stack)
    if update_exception:
        session.last_exception = final_exception
