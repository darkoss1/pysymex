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

"""Detector issue suppression through bytecode exception-handler analysis."""

from __future__ import annotations

from dataclasses import dataclass
import dis
from typing import cast

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.analysis.domains.exceptions.analyzer.bytecode import (
    catches_name,
    cleanup_replaces_original_at,
    cleanup_reraise_at,
    infer_caught_at,
    infer_with_manager_call_at,
)
from pysymex.analysis.domains.exceptions.analyzer.context_managers import (
    known_with_manager_suppresses,
)
from pysymex.core.state.record import VMState
from pysymex.core.state.types import is_bound
from pysymex.execution.detectors.publication import should_replace_dynamic_exit_issue
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.common.exceptions.helpers import find_exception_entry

__all__ = ["issue_is_caught_by_exception_handler"]


@dataclass(frozen=True, slots=True)
class _StateNameLookup:
    """Resolve names as CPython would for the active frame's visible stores."""

    state: VMState

    def get(self, key: str) -> object | None:
        """Return a local binding when present, otherwise a global binding."""
        local_value = self.state.get_local(key)
        if is_bound(local_value):
            return local_value
        return self.state.get_global(key)


def issue_is_caught_by_exception_handler(
    dispatcher: OpcodeDispatcher,
    issue: Issue,
    instr: dis.Instruction,
    state: VMState,
) -> bool:
    """Return whether bytecode exception tables would catch this issue type."""
    exception_name = _exception_name_for_issue(issue, instr)
    if exception_name is None:
        return False
    from pysymex.execution.opcodes.common.control.sequence_iteration import (
        next_iteration_handles_exception,
        sequence_getitem_iteration_handles_exception,
    )
    from pysymex.execution.opcodes.common.control.callable_sentinel_iteration import (
        callable_sentinel_iteration_handles_exception,
    )

    if sequence_getitem_iteration_handles_exception(state, exception_name):
        return True
    if next_iteration_handles_exception(state, exception_name):
        return True
    if callable_sentinel_iteration_handles_exception(state, exception_name):
        return True
    if should_replace_dynamic_exit_issue(state):
        return _active_exception_handler_catches(dispatcher, state, instr.offset, exception_name)
    return _exception_handler_catches(dispatcher, state, instr.offset, exception_name)


def _exception_name_for_issue(issue: Issue, instr: dis.Instruction) -> str | None:
    """Map a reported issue kind/message to a CPython exception name when possible."""
    if issue.kind == IssueKind.DIVISION_BY_ZERO:
        return "ZeroDivisionError"
    if issue.kind == IssueKind.TYPE_ERROR:
        return "TypeError"
    if issue.kind == IssueKind.VALUE_ERROR:
        return "ValueError"
    if issue.kind == IssueKind.OVERFLOW:
        return "OverflowError"
    if issue.kind == IssueKind.ATTRIBUTE_ERROR:
        return "AttributeError"
    if issue.kind == IssueKind.INDEX_ERROR:
        return "IndexError"
    if issue.kind == IssueKind.KEY_ERROR:
        return "KeyError"
    if issue.kind == IssueKind.NAME_ERROR:
        return "NameError"
    if issue.kind == IssueKind.UNBOUND_VARIABLE:
        return "NameError"
    if issue.kind == IssueKind.NULL_DEREFERENCE:
        return _null_dereference_exception_name(instr)
    if issue.kind != IssueKind.UNHANDLED_EXCEPTION:
        return None

    if ": " in issue.message:
        candidate = issue.message.rsplit(": ", 1)[-1].strip()
        if candidate:
            return candidate.split("(", 1)[0].split("[", 1)[0].strip()
    if "] " in issue.message:
        tail = issue.message.split("] ", 1)[1]
        candidate = tail.split(":", 1)[0].strip()
        if candidate:
            return candidate
    return None


def _null_dereference_exception_name(instr: dis.Instruction) -> str | None:
    """Return the CPython exception raised by dereferencing ``None`` at *instr*."""
    if instr.opname == "BINARY_SUBSCR":
        return "TypeError"
    if instr.opname in {
        "DELETE_ATTR",
        "LOAD_ATTR",
        "LOAD_METHOD",
        "LOAD_SUPER_ATTR",
        "STORE_ATTR",
    }:
        return "AttributeError"
    return None


def _exception_handler_catches(
    dispatcher: OpcodeDispatcher,
    state: VMState,
    offset: int,
    exception_name: str,
) -> bool:
    """Return whether any active or caller frame would catch ``exception_name``."""
    if _active_exception_handler_catches(dispatcher, state, offset, exception_name):
        return True
    from pysymex.execution.opcodes.common.functions.attribute.protocols import (
        GETATTR_DEFAULT_PROTOCOL_METHODS,
    )

    active_instructions = dispatcher.instructions
    for frame in reversed(state.call_stack):
        if (
            exception_name == "AttributeError"
            and frame.protocol_method in GETATTR_DEFAULT_PROTOCOL_METHODS
        ):
            return True
        if frame.caller_instructions is None or frame.caller_offset is None:
            continue
        caller_instructions = cast("list[dis.Instruction]", frame.caller_instructions)
        dispatcher.set_instructions(caller_instructions)
        if _active_exception_handler_catches(
            dispatcher,
            state,
            frame.caller_offset,
            exception_name,
        ):
            dispatcher.set_instructions(active_instructions)
            return True
    dispatcher.set_instructions(active_instructions)
    return False


def _active_exception_handler_catches(
    dispatcher: OpcodeDispatcher,
    state: VMState,
    offset: int,
    exception_name: str,
) -> bool:
    """Walk exception-table entries from ``offset`` until a handler matches."""
    visited: set[int] = set()
    while offset not in visited:
        visited.add(offset)
        handler_index = dispatcher.find_exception_handler(offset)
        if handler_index is None:
            return False
        handler_offset = dispatcher.instructions[handler_index].offset
        caught_names = infer_caught_at(dispatcher.instructions, handler_offset)
        entry = find_exception_entry(dispatcher, offset)
        protected_start = getattr(entry, "start", None)
        if isinstance(protected_start, int):
            suppression = infer_with_manager_call_at(
                dispatcher.instructions,
                protected_start,
                handler_offset,
            )
            if suppression is not None and known_with_manager_suppresses(
                _StateNameLookup(state),
                exception_name,
                *suppression,
            ):
                return True
        if catches_name(exception_name, caught_names):
            return True
        if cleanup_replaces_original_at(dispatcher.instructions, handler_offset):
            return True
        cleanup_reraise = cleanup_reraise_at(dispatcher.instructions, handler_offset)
        if cleanup_reraise is None:
            return False
        offset = cleanup_reraise
    return False
