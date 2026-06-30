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

"""Bytecode exception-handler walking for detector suppression."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.state.types import is_bound
from pysymex._internal.execution.detectors.suppression.bytecode import SuppressionBytecodeOps
from pysymex._internal.execution.detectors.suppression.managers import SuppressionManagerPolicy
from pysymex._internal.execution.opcodes.common.exceptions.exception_flow import ExceptionFlow

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher


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


def exception_handler_catches(
    dispatcher: OpcodeDispatcher,
    state: VMState,
    offset: int,
    exception_name: str,
) -> bool:
    """Return whether any active or caller frame would catch ``exception_name``."""
    if active_exception_handler_catches(dispatcher, state, offset, exception_name):
        return True
    from pysymex._internal.execution.opcodes.common.control.match.pattern_ops import (
        MATCH_CLASS_ATTR_PROTOCOL,
    )
    from pysymex._internal.execution.opcodes.common.functions.attribute.protocols.constants import (
        GETATTR_ATTRIBUTE_ERROR_CHAIN_PROTOCOL_METHODS,
        GETATTR_DEFAULT_PROTOCOL_METHODS,
    )

    getattr_attribute_error_protocols = (
        GETATTR_DEFAULT_PROTOCOL_METHODS | GETATTR_ATTRIBUTE_ERROR_CHAIN_PROTOCOL_METHODS
    )
    attribute_error_protocols = getattr_attribute_error_protocols | {MATCH_CLASS_ATTR_PROTOCOL}
    active_instructions = dispatcher.instructions
    for frame in reversed(state.call_stack):
        if (
            exception_name == "AttributeError"
            and frame.protocol_method in attribute_error_protocols
        ):
            return True
        if frame.caller_instructions is None or frame.caller_offset is None:
            continue
        caller_instructions = cast("list[dis.Instruction]", frame.caller_instructions)
        dispatcher.set_instructions(caller_instructions)
        if active_exception_handler_catches(
            dispatcher,
            state,
            frame.caller_offset,
            exception_name,
        ):
            dispatcher.set_instructions(active_instructions)
            return True
    dispatcher.set_instructions(active_instructions)
    return False


def active_exception_handler_catches(
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
        caught_names = SuppressionBytecodeOps.infer_caught_at(
            dispatcher.instructions,
            handler_offset,
        )
        entry = ExceptionFlow.entry_at(dispatcher, offset)
        protected_start = getattr(entry, "start", None)
        if isinstance(protected_start, int):
            suppression = SuppressionBytecodeOps.infer_with_manager_call_at(
                dispatcher.instructions,
                protected_start,
                handler_offset,
            )
            if suppression is not None and SuppressionManagerPolicy.known_suppresses(
                _StateNameLookup(state),
                exception_name,
                *suppression,
            ):
                return True
        if SuppressionBytecodeOps.catches_name(exception_name, caught_names):
            return True
        if SuppressionBytecodeOps.cleanup_replaces_original_at(
            dispatcher.instructions,
            handler_offset,
        ):
            return True
        cleanup_reraise = SuppressionBytecodeOps.cleanup_reraise_at(
            dispatcher.instructions,
            handler_offset,
        )
        if cleanup_reraise is None:
            return False
        offset = cleanup_reraise
    return False
