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

"""Restore caller ``locals``/``globals`` after nested calls and protocol suspension.

Copies mutated argument aliases back into the caller frame, merges protocol return
normalization results, and applies deferred issues recorded during the callee. Used by
``RETURN_VALUE`` / ``RETURN_CONST`` handlers before advancing the caller PC.

Side Effects:
    Mutates caller-local COW dicts and may append issues to the active path.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.analysis.detectors import Issue
    from pysymex.typing import StackValue
    from pysymex.core.memory.cow.collections import CowDict
    from pysymex.core.state.types import CallFrame
    from pysymex.core.state.record import VMState


def apply_argument_alias_updates(
    state: VMState,
    frame: CallFrame,
) -> CowDict[str, StackValue]:
    """Return isolated caller locals refreshed with mutated direct argument aliases."""
    updated = frame.local_vars.cow_fork()
    if not frame.argument_aliases:
        return updated

    for arg_name, original in frame.argument_aliases:
        current = state.local_vars.get(arg_name, original)
        if current is original:
            continue
        for local_name, local_value in tuple(updated.items()):
            if local_value is original:
                updated[str(local_name)] = current
        for global_name, global_value in tuple(state.global_vars.items()):
            if global_value is original:
                state = state.set_global(str(global_name), current)
    return updated


def restore_caller_stack(state: VMState, frame: CallFrame) -> None:
    """Restore the caller operand stack after callee-local stack reshaping."""
    if frame.caller_stack is None:
        state.stack = state.stack[: frame.stack_depth]
        return
    state.stack = list(frame.caller_stack)


def collect_return_postcondition_issues(
    state: VMState, return_value: object, config: object | None
) -> list[Issue]:
    """Evaluate enabled return obligations without merging clause outcomes."""
    if not state.contract_frames:
        return []
    contract_frame = state.contract_frames.pop()
    if not (config and getattr(config, "enable_contract_verification", False)):
        return []
    from pysymex.contracts.binding import runtime_frame_parts

    frame_parts = runtime_frame_parts(contract_frame)
    if frame_parts is None:
        raise TypeError(f"Invalid contract frame value: {type(contract_frame).__name__}")
    function, old_symbols, effect_start_index = frame_parts
    if not callable(function):
        raise TypeError(f"Invalid contract frame value: {type(function).__name__}")
    from pysymex.contracts.effects import check_effect_obligations

    check_effect_obligations(state, function, state.write_events[effect_start_index:])
    issues: list[Issue] = []
    if getattr(config, "check_contract_class_invariants", True):
        from pysymex.contracts.invariants import InvariantCheckPoint, check_class_invariants

        issues.extend(check_class_invariants(state, function, InvariantCheckPoint.EXIT))
    if not getattr(config, "check_contract_postconditions", True):
        return issues
    from pysymex.contracts.runtime.returns import inject_postconditions

    issues.extend(
        inject_postconditions(state, function, return_value, config, old_symbols=old_symbols)
    )
    return issues
