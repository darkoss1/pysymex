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

"""Opcode dispatcher runtime class."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.dispatch.dispatcher.registry import (
    clear_handlers,
    global_handler_module,
    handler_decorator,
    has_registered_handler,
    register_handler,
    registered_opcode_names,
)
from pysymex._internal.execution.dispatch.dispatcher.stream import (
    register_stream_exception_entries,
    select_instruction_stream,
    store_active_exception_entries,
)
from pysymex._internal.execution.dispatch.exception.index import handler_index_for_offset

if TYPE_CHECKING:
    import dis
    from collections.abc import Callable

    from pysymex._internal.config.execution.settings import ExecutionConfig
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.types import OpcodeHandler
    from pysymex._internal.execution.dispatch.result import OpcodeResult


class OpcodeDispatcher:
    """Own per-instance and global opcode handler registries plus stream metadata.

    The dispatcher selects a handler and passes through its ``OpcodeResult``;
    individual handlers own stack effects, forking, constraint updates, and issue emission.
    """

    _global_handlers: dict[str, OpcodeHandler] = {}
    _global_handler_generation: int = 0

    def __init__(self) -> None:
        """Initialize the dispatcher."""
        self._handlers: dict[str, OpcodeHandler] = {}
        self._local_handler_generation = 0
        self._combined_handlers: dict[str, OpcodeHandler] | None = None
        self._combined_handler_generation: tuple[int, int] | None = None
        self.instructions: list[dis.Instruction] = []
        self._offset_to_index: dict[int, int] = {}
        self.cross_function: object | None = None
        self.config: ExecutionConfig | None = None
        self._exception_entries: list[object] = []
        self._exception_entries_by_stream: dict[tuple[int, ...], list[object]] = {}
        self._exception_handler_by_offset: dict[int, int | None] = {}

    def register(self, *opcodes: str) -> Callable[[OpcodeHandler], OpcodeHandler]:
        """Return a decorator registering ``handler`` for instance-local opcodes."""
        return handler_decorator(self._handlers, opcodes)

    def register_handler(self, opcode: str, handler: OpcodeHandler) -> None:
        """Associate one instance-local opcode name with ``handler``."""
        register_handler(self._handlers, opcode, handler)
        self._local_handler_generation += 1
        self._combined_handlers = None
        self._combined_handler_generation = None

    def set_instructions(self, instructions: list[dis.Instruction]) -> None:
        """Set the active instruction stream and select its exception metadata."""
        selection = select_instruction_stream(
            instructions,
            self.instructions,
            self._exception_entries,
            self._exception_entries_by_stream,
        )
        if selection is None:
            return
        self.instructions = selection.instructions
        self._offset_to_index = selection.offset_to_index
        self._exception_handler_by_offset.clear()
        self._exception_entries = selection.exception_entries

    def set_exception_entries(self, entries: list[object]) -> None:
        """Store exception-table entries for the active instruction stream."""
        self._exception_entries = store_active_exception_entries(
            self.instructions,
            entries,
            self._exception_entries_by_stream,
        )
        self._exception_handler_by_offset.clear()

    def register_exception_entries(
        self,
        instructions: list[dis.Instruction],
        entries: list[object],
    ) -> None:
        """Register exception metadata for a paused caller or callee stream."""
        register_stream_exception_entries(
            instructions,
            entries,
            self._exception_entries_by_stream,
        )

    def find_exception_handler(self, offset: int) -> int | None:
        """Return the most nested registered handler index covering ``offset``."""
        return handler_index_for_offset(
            offset,
            self._exception_entries,
            self._offset_to_index,
            self._exception_handler_by_offset,
        )

    def get_instruction(self, index: int) -> dis.Instruction | None:
        """Return instruction by index, or ``None`` when out of bounds."""
        if 0 <= index < len(self.instructions):
            return self.instructions[index]
        return None

    def offset_to_index(self, offset: int) -> int | None:
        """Convert bytecode offset to instruction index."""
        return self._offset_to_index.get(offset)

    def dispatch(self, instr: dis.Instruction, state: VMState) -> OpcodeResult:
        """Invoke the registered handler for ``instr``."""
        generation = (
            self._local_handler_generation,
            OpcodeDispatcher._global_handler_generation,
        )
        combined = self._combined_handlers
        if combined is None or self._combined_handler_generation != generation:
            combined = {**OpcodeDispatcher._global_handlers, **self._handlers}
            self._combined_handlers = combined
            self._combined_handler_generation = generation
        handler = combined.get(instr.opname)
        if handler is None:
            msg = f"Opcode not supported: {instr.opname}"
            raise RuntimeError(msg)
        return handler(instr, state, self)

    def has_handler(self, opcode: str) -> bool:
        """Return whether a handler is registered for an opcode."""
        return has_registered_handler(self._handlers, OpcodeDispatcher._global_handlers, opcode)

    def registered_opcodes(self) -> set[str]:
        """Return instance-local and global registered opcode names."""
        return registered_opcode_names(self._handlers, OpcodeDispatcher._global_handlers)

    @classmethod
    def register_global(cls, opcode: str, handler: OpcodeHandler) -> None:
        """Associate an opcode with a process-wide handler entry."""
        register_handler(cls._global_handlers, opcode, handler)
        cls._global_handler_generation += 1

    @classmethod
    def global_handler_module(cls, opcode: str) -> str | None:
        """Return the module name for a globally registered opcode handler."""
        return global_handler_module(cls._global_handlers, opcode)

    @classmethod
    def clear_global_handlers(cls, module_prefixes: tuple[str, ...] | None = None) -> None:
        """Clear globally registered opcode handlers."""
        clear_handlers(cls._global_handlers, module_prefixes)
        cls._global_handler_generation += 1

    def instruction_count(self) -> int:
        """Return the number of instructions in the active stream."""
        return len(self.instructions)

    def __repr__(self) -> str:
        return f"OpcodeDispatcher({len(self._handlers)} handlers)"
