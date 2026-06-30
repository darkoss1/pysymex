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

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.effects.events import WriteEvent, WriteKind
from pysymex._internal.core.types.containers.objects import SymbolicObject

if TYPE_CHECKING:
    from pysymex._internal.analysis.detectors.detector.types import Issue
    from pysymex._internal.core.memory.cow.dicts import CowDict
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import CallFrame
    from pysymex._internal.typing.protocols import StackValue


def apply_argument_alias_updates(
    state: VMState,
    frame: CallFrame,
) -> CowDict[str, StackValue]:
    """Return isolated caller locals refreshed with mutated direct argument aliases."""
    updated = frame.local_vars.cow_fork()
    if not frame.argument_aliases:
        return updated

    with updated.mutate() as mut:
        for arg_name, original in frame.argument_aliases:
            current = state.local_vars.get(arg_name, original)
            current = _stack_cell_contents_for_value(state, current)
            if current is original:
                continue
            for local_name in list(updated):
                if mut[local_name] is original:
                    mut[str(local_name)] = current
            for global_name, global_value in tuple(state.global_vars.items()):
                if global_value is original:
                    state = state.set_global(str(global_name), current)
    return updated


def apply_write_event_scope_updates(state: VMState, frame: CallFrame) -> None:
    """Rewrite callee write events into caller-visible roots before frame restoration."""
    start_index = frame.write_event_start_index
    if start_index >= len(state.write_events):
        return

    scoped_events: list[WriteEvent] = []
    for event in state.write_events[start_index:]:
        scoped = _caller_scoped_write_event(state, frame, event)
        if scoped is not None:
            scoped_events.append(scoped)
    state.write_events = [*state.write_events[:start_index], *scoped_events]


def restore_caller_stack(state: VMState, frame: CallFrame) -> None:
    """Restore the caller operand stack after callee-local stack reshaping."""
    if frame.caller_stack is None:
        state.stack = state.stack[: frame.stack_depth]
        return
    state.stack = list(frame.caller_stack)


def collect_return_postcondition_issues(
    state: VMState,
    return_value: object,
    config: object | None,
    *,
    expected_function_name: str | None = None,
) -> list[Issue]:
    """Evaluate enabled return obligations without merging clause outcomes."""
    if not state.contract_frames:
        return []
    if not (config and getattr(config, "enable_contract_verification", False)):
        return []
    from pysymex._internal.contracts.binding.snapshots import runtime_frame_parts

    frame_parts = runtime_frame_parts(state.contract_frames[-1])
    if frame_parts is None:
        contract_frame = state.contract_frames[-1]
        msg = f"Invalid contract frame value: {type(contract_frame).__name__}"
        raise TypeError(msg)
    function, old_symbols, effect_start_index, effect_visible_roots = frame_parts
    if not callable(function):
        msg = f"Invalid contract frame value: {type(function).__name__}"
        raise TypeError(msg)
    if (
        expected_function_name is not None
        and getattr(function, "__name__", None) != expected_function_name
    ):
        return []
    state.contract_frames.pop()
    from pysymex._internal.contracts.effects.checks import check_effect_obligations

    check_effect_obligations(
        state,
        function,
        state.write_events[effect_start_index:],
        visible_roots=effect_visible_roots,
    )
    issues: list[Issue] = []
    if getattr(config, "check_contract_class_invariants", True):
        from pysymex._internal.contracts.invariants.checks import check_class_invariants
        from pysymex._internal.contracts.invariants.policy import InvariantCheckPoint

        issues.extend(check_class_invariants(state, function, InvariantCheckPoint.EXIT))
    if not getattr(config, "check_contract_postconditions", True):
        return issues
    from pysymex._internal.contracts.runtime.returns import inject_postconditions

    issues.extend(
        inject_postconditions(state, function, return_value, config, old_symbols=old_symbols),
    )
    return issues


def _caller_scoped_write_event(
    state: VMState,
    frame: CallFrame,
    event: WriteEvent,
) -> WriteEvent | None:
    """Return a caller-relative event, or ``None`` for non-escaping callee-local writes."""
    root = _write_location_root(event.location)
    if root is None or event.kind not in {WriteKind.ATTRIBUTE, WriteKind.ITEM}:
        return event
    if root not in state.local_vars:
        return event

    caller_root = _caller_root_for_value(state, frame, state.local_vars[root])
    if caller_root is None:
        return None
    if caller_root == root:
        return event
    return WriteEvent(
        event.kind,
        _replace_write_location_root(event.location, root, caller_root),
        event.pc,
        event.precise,
        event.source,
    )


def _caller_root_for_value(state: VMState, frame: CallFrame, value: object) -> str | None:
    """Return the caller-visible root for a returned callee local value."""
    resolved_value = _cell_contents_for_value(state, value)
    for name, candidate in frame.local_vars.items():
        if _same_modeled_identity(candidate, value):
            return str(name)
        if resolved_value is not value and _same_modeled_identity(candidate, resolved_value):
            return str(name)
    for name, candidate in state.global_vars.items():
        if _same_modeled_identity(candidate, value):
            return f"global.{name}"
        if resolved_value is not value and _same_modeled_identity(candidate, resolved_value):
            return f"global.{name}"
    return None


def _cell_contents_for_value(state: VMState, value: object) -> object:
    """Return closure-cell contents when *value* is a modeled cell object."""
    if not (isinstance(value, SymbolicObject) and value.name.startswith("cell_")):
        return value
    if value.address == -1:
        return value
    cell_value = state.memory.get(value.address)
    return value if cell_value is None else cell_value


def _stack_cell_contents_for_value(state: VMState, value: StackValue) -> StackValue:
    """Return closure-cell contents while preserving the stack-value type contract."""
    return cast("StackValue", _cell_contents_for_value(state, value))


def _same_modeled_identity(left: object, right: object) -> bool:
    """Return whether two stack values are the same modeled mutation target."""
    if left is right:
        return True
    if isinstance(left, SymbolicObject) and isinstance(right, SymbolicObject):
        return left.address != -1 and left.address == right.address
    return False


def _write_location_root(location: str) -> str | None:
    """Return the root segment of a write-event location."""
    if not location or location.startswith("*"):
        return None
    if location.startswith("global."):
        parts = location.split(".", 2)
        return ".".join(parts[:2]) if len(parts) >= 2 else location
    item_marker = location.find("[")
    attr_marker = location.find(".")
    markers = [marker for marker in (item_marker, attr_marker) if marker != -1]
    if not markers:
        return location
    return location[: min(markers)]


def _replace_write_location_root(location: str, old_root: str, new_root: str) -> str:
    """Return *location* with its root rewritten to *new_root*."""
    if location == old_root:
        return new_root
    return f"{new_root}{location[len(old_root) :]}"
