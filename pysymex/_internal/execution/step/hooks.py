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

"""Plugin hook execution for one-instruction execution steps."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.result import OpcodeResult
    from pysymex._internal.execution.step.types import HookMap

logger = get_logger(__name__)


def run_pre_step_hooks(*, hook_owner: object, hooks: HookMap, state: VMState) -> None:
    """Run pre-step hooks before fetching or dispatching an instruction."""
    for hook in hooks.get("pre_step", ()):
        hook(hook_owner, state)


def run_post_step_hooks(
    *,
    hook_owner: object,
    hooks: HookMap,
    result: OpcodeResult,
    fallback_state: VMState,
    instr: dis.Instruction,
) -> None:
    """Run post-step hooks for successor states, logging plugin failures."""
    post_step_hooks = hooks.get("post_step")
    if not post_step_hooks:
        return
    states_to_hook = result.new_states or (fallback_state,)
    for next_state in states_to_hook:
        for hook in post_step_hooks:
            try:
                hook(hook_owner, next_state, instr)
            except Exception:
                logger.exception("Plugin hook execution failed")
