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

"""Opcode handler registry and instruction-stream dispatch machinery."""

from __future__ import annotations

import dis
from collections.abc import Callable
from typing import TYPE_CHECKING

from pysymex.core.bytecode import instruction_stream_key
from pysymex.execution.dispatch.result import OpcodeResult

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState


OpcodeHandler = Callable[[dis.Instruction, "VMState", "OpcodeDispatcher"], OpcodeResult]


class OpcodeDispatcher:
    """Own per-instance and global opcode handler registries plus stream metadata.

    The dispatcher selects a handler and passes through its ``OpcodeResult``;
    individual handlers own stack effects, forking, constraint updates, and
    issue emission.
    """

    _global_handlers: dict[str, OpcodeHandler] = {}

    def __init__(self) -> None:
        """Initialize the dispatcher."""
        self._handlers: dict[str, OpcodeHandler] = {}
        self.instructions: list[dis.Instruction] = []
        self._offset_to_index: dict[int, int] = {}
        self.cross_function: object | None = None
        self._exception_entries: list[object] = []
        self._exception_entries_by_stream: dict[tuple[int, ...], list[object]] = {}
        self._exception_handler_by_offset: dict[int, int | None] = {}

    def register(self, *opcodes: str) -> Callable[[OpcodeHandler], OpcodeHandler]:
        """Return a decorator registering ``handler`` for instance-local opcodes.

        Args:
            *opcodes: Opcode name strings to register.

        Returns:
            A decorator that associates the handler with the given opcodes.
        """

        def decorator(handler: OpcodeHandler) -> OpcodeHandler:
            for opcode in opcodes:
                self._handlers[opcode] = handler
            return handler

        return decorator

    def register_handler(self, opcode: str, handler: OpcodeHandler) -> None:
        """Associate one instance-local opcode name with ``handler``.

        Args:
            opcode: The name of the opcode to register.
            handler: The callback handler for this opcode.
        """
        self._handlers[opcode] = handler

    def set_instructions(self, instructions: list[dis.Instruction]) -> None:
        """Set the active instruction stream and select its exception metadata.

        Args:
            instructions: List of instructions representing the new active stream.
        """
        if instructions is self.instructions:
            return
        previous_stream_was_empty = not self.instructions
        pending_entries = list(self._exception_entries)
        self.instructions = instructions
        self._offset_to_index = {instr.offset: idx for idx, instr in enumerate(instructions)}
        self._exception_handler_by_offset.clear()
        stream_key = instruction_stream_key(instructions)
        registered_entries = self._exception_entries_by_stream.get(stream_key)
        if registered_entries is not None:
            self._exception_entries = list(registered_entries)
        elif previous_stream_was_empty and pending_entries:
            self._exception_entries = pending_entries
            self._exception_entries_by_stream[stream_key] = list(pending_entries)
        else:
            self._exception_entries = []

    def set_exception_entries(self, entries: list[object]) -> None:
        """Store exception-table entries for the active instruction stream.

        Args:
            entries: Exception metadata list for the current stream.
        """
        self._exception_entries = list(entries)
        self._exception_entries_by_stream[instruction_stream_key(self.instructions)] = list(entries)
        self._exception_handler_by_offset.clear()

    def register_exception_entries(
        self, instructions: list[dis.Instruction], entries: list[object]
    ) -> None:
        """Register exception metadata for a paused caller or callee stream.

        Args:
            instructions: Instruction list to register metadata for.
            entries: Exception metadata entries for those instructions.
        """
        self._exception_entries_by_stream[instruction_stream_key(instructions)] = list(entries)

    def find_exception_handler(self, offset: int) -> int | None:
        """Return the most nested registered handler index covering ``offset``.

        Args:
            offset: The bytecode offset to search for.

        Returns:
            The instruction index of the target exception handler, or None if not found.
        """
        if offset in self._exception_handler_by_offset:
            return self._exception_handler_by_offset[offset]

        best_idx: int | None = None
        best_start: int | None = None
        best_end: int | None = None
        for entry in self._exception_entries:
            start = getattr(entry, "start", None)
            end = getattr(entry, "end", None)
            target = getattr(entry, "target", None)
            if start is None or end is None or target is None:
                continue
            if not (start <= offset < end):
                continue
            idx = self._offset_to_index.get(target)
            if idx is None:
                continue
            if best_start is None:
                best_idx = idx
                best_start = start
                best_end = end
                continue
            if start > best_start:
                best_idx = idx
                best_start = start
                best_end = end
                continue
            if start == best_start and best_end is not None and end < best_end:
                best_idx = idx
                best_end = end

        self._exception_handler_by_offset[offset] = best_idx
        return best_idx

    def get_instruction(self, index: int) -> dis.Instruction | None:
        """Get instruction by index.

        Args:
            index: The positional instruction index.

        Returns:
            The instruction at that index, or None if index is out of bounds.
        """
        if 0 <= index < len(self.instructions):
            return self.instructions[index]
        return None

    def offset_to_index(self, offset: int) -> int | None:
        """Convert bytecode offset to instruction index.

        Args:
            offset: The bytecode offset of the instruction.

        Returns:
            The instruction index, or None if offset is not found.
        """
        return self._offset_to_index.get(offset)

    def dispatch(self, instr: dis.Instruction, state: VMState) -> OpcodeResult:
        """Invoke the registered handler for ``instr``.

        Args:
            instr: The instruction to dispatch.
            state: The current symbolic VMState.

        Returns:
            The OpcodeResult generated by the matched handler.

        Raises:
            RuntimeError: If no handler is registered locally or globally for the opcode name.
        """
        handler = self._handlers.get(instr.opname)
        if handler is None:
            handler = OpcodeDispatcher._global_handlers.get(instr.opname)
        if handler is None:
            raise RuntimeError(f"Opcode not supported: {instr.opname}")
        return handler(instr, state, self)

    def has_handler(self, opcode: str) -> bool:
        """Check if a handler is registered for an opcode.

        Args:
            opcode: The opcode name to check.

        Returns:
            True if registered locally or globally, False otherwise.
        """
        return opcode in self._handlers or opcode in OpcodeDispatcher._global_handlers

    def registered_opcodes(self) -> set[str]:
        """Return instance-local and global registered opcode names.

        Returns:
            A set of all registered opcode name strings.
        """
        return set(self._handlers.keys()) | set(OpcodeDispatcher._global_handlers.keys())

    @classmethod
    def register_global(cls, opcode: str, handler: OpcodeHandler) -> None:
        """Associate an opcode with a process-wide handler entry.

        Args:
            opcode: The opcode name to register globally.
            handler: The global opcode handler to register.
        """
        cls._global_handlers[opcode] = handler

    @classmethod
    def global_handler_module(cls, opcode: str) -> str | None:
        """Return the module name for a globally registered opcode handler.

        Args:
            opcode: The opcode name.

        Returns:
            The module name string containing the handler, or None.
        """
        handler = cls._global_handlers.get(opcode)
        if handler is None:
            return None
        return handler.__module__

    @classmethod
    def clear_global_handlers(cls, module_prefixes: tuple[str, ...] | None = None) -> None:
        """Clear globally registered opcode handlers.

        When ``module_prefixes`` is provided, only handlers whose defining module
        starts with one of those prefixes are removed.

        Args:
            module_prefixes: Optional prefixes to filter which handlers to clear.
        """
        if module_prefixes is None:
            cls._global_handlers.clear()
            return
        for opcode, handler in tuple(cls._global_handlers.items()):
            if handler.__module__.startswith(module_prefixes):
                del cls._global_handlers[opcode]

    def instruction_count(self) -> int:
        """Get the number of instructions in the active stream.

        Returns:
            The total instruction count.
        """
        return len(self.instructions)

    def __repr__(self) -> str:
        return f"OpcodeDispatcher({len(self._handlers)} handlers)"


def opcode_handler(*opcodes: str) -> Callable[[OpcodeHandler], OpcodeHandler]:
    """Return a decorator registering a handler in the process-wide registry.

    Args:
        *opcodes: Opcode names to register.

    Returns:
        A decorator callable.
    """

    def decorator(handler: OpcodeHandler) -> OpcodeHandler:
        for opcode in opcodes:
            OpcodeDispatcher.register_global(opcode, handler)
        return handler

    return decorator
