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

"""Opcode dispatch orchestration for one-instruction execution steps."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.step.hooks import run_post_step_hooks
from pysymex._internal.execution.step.snapshots import record_dispatch_snapshots
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.dispatch.result import OpcodeResult
    from pysymex._internal.execution.session.state.core import ExecutionSession
    from pysymex._internal.execution.step.types import HookMap

logger = get_logger(__name__)


def dispatch_instruction(
    *,
    dispatcher: OpcodeDispatcher,
    session: ExecutionSession,
    hook_owner: object,
    hooks: HookMap,
    instr: dis.Instruction,
    state: VMState,
) -> OpcodeResult:
    """Dispatch one opcode, snapshot hook-visible state when needed, and run hooks."""
    if logger.state.trace_enabled:
        logger.trace(
            "dispatch opcode path_id=%d pc=%d offset=%d opname=%s stack=%d constraints=%d",
            state.path_id,
            state.pc,
            instr.offset,
            instr.opname,
            len(state.stack),
            len(state.path_constraints),
        )
    result = dispatcher.dispatch(instr, state)
    if logger.state.trace_enabled:
        logger.trace(
            "opcode result path_id=%d pc=%d new_states=%d issues=%d terminal=%s",
            state.path_id,
            state.pc,
            len(result.new_states),
            len(result.issues),
            result.terminal,
        )

    if _should_record_dispatch_snapshots(hooks=hooks, result=result):
        record_dispatch_snapshots(session=session, state=state)
    run_post_step_hooks(
        hook_owner=hook_owner,
        hooks=hooks,
        result=result,
        fallback_state=state,
        instr=instr,
    )
    return result


def _should_record_dispatch_snapshots(*, hooks: HookMap, result: OpcodeResult) -> bool:
    """Return whether hook-observable dispatch snapshots are needed."""
    if hooks.get("post_step"):
        return True
    if result.issues and hooks.get("on_issue"):
        return True
    return len(result.new_states) >= 2 and bool(hooks.get("on_fork"))
