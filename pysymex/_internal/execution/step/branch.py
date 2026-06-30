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

"""Branch-state duplicate pruning for one-instruction execution steps."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from pysymex._internal.execution.constants import BRANCH_OPCODES
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.session.state.core import ExecutionSession
    from pysymex._internal.execution.step.types import HookMap

logger = get_logger(__name__)

DUPLICATE_STATE_PRUNE_REASON: Final = "duplicate_state"


def is_branch_or_jump_instruction(instr: dis.Instruction) -> bool:
    """Return whether an instruction should participate in duplicate-state pruning."""
    return instr.opname in BRANCH_OPCODES or "JUMP" in instr.opname


def build_state_key(state: VMState) -> tuple[int, ...]:
    """Build the composite key used for duplicate branch-state pruning."""
    return (
        state.hash_value(),
        state.pc,
        len(state.path_constraints),
        len(state.stack),
        len(state.call_stack),
        len(state.block_stack),
    )


def record_duplicate_branch_state(
    *,
    session: ExecutionSession,
    state: VMState,
    instr: dis.Instruction,
    hook_owner: object,
    hooks: HookMap,
) -> bool:
    """Record or prune a branch/jump state using the session duplicate-state set.

    Returns:
        ``True`` when the state was pruned as a duplicate; ``False`` otherwise.

    """
    if not is_branch_or_jump_instruction(instr):
        return False

    state_key = build_state_key(state)
    if state_key in session.visited_states:
        session.paths_pruned += 1
        for hook in hooks.get("on_prune", ()):
            try:
                hook(hook_owner, state, DUPLICATE_STATE_PRUNE_REASON)
            except Exception:
                logger.exception("Plugin hook execution failed")
        return True

    session.visited_states.add(state_key)
    return False
