# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Opcode dispatcher with registration system.
This module provides a decorator-based system for registering opcode handlers,
allowing modular organization of bytecode interpretation.
"""

from __future__ import annotations

import dis
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.analysis.detectors import Issue
    from pysymex.core.state import VMState


@dataclass
class OpcodeResult:
    """Result of executing an opcode.
    Attributes:
        new_states: List of new VM states to explore.
        issues: List of issues detected during execution.
        terminal: bool: Whether this opcode terminates execution.
    """

    new_states: list[VMState]
    issues: list[Issue]
    terminal: bool = False

    @staticmethod
    def _collect_pending(state: VMState) -> list[Issue]:
        issues = []
        pending = state.pending_taint_issues
        try:
            from pysymex.analysis.detectors import Issue as RuntimeIssue

            issues.extend(issue for issue in pending if isinstance(issue, RuntimeIssue))
        except Exception:
            issues.extend(issue for issue in pending if issue is not None)
        state.pending_taint_issues = []
        return issues

    @classmethod
    def continue_with(cls, state: VMState) -> OpcodeResult:
        """Continue execution with a single state."""
        return cls(new_states=[state], issues=cls._collect_pending(state))

    @classmethod
    def branch(cls, states: list[VMState], issues: list[Issue] | None = None) -> OpcodeResult:
        """Branch into multiple states."""
        all_issues = list(issues) if issues is not None else []
        for s in states:
            all_issues.extend(cls._collect_pending(s))
        return cls(new_states=states, issues=all_issues)

    @classmethod
    def fork(cls, states: list[VMState], issues: list[Issue | None]) -> OpcodeResult:
        """Fork into multiple states with specific issues for some states."""
        all_issues = []
        for state, issue in zip(states, issues, strict=False):
            all_issues.extend(cls._collect_pending(state))
            if issue is not None:
                all_issues.append(issue)
        return cls(new_states=states, issues=all_issues)

    @staticmethod
    def terminate() -> OpcodeResult:
        """Terminate this execution path."""
        return OpcodeResult(new_states=[], issues=[], terminal=True)

    @classmethod
    def with_issue(cls, state: VMState, issue: Issue) -> OpcodeResult:
        """Continue with an issue detected."""
        issues = cls._collect_pending(state)
        issues.append(issue)
        return cls(new_states=[state], issues=issues)

    @classmethod
    def error(cls, issue: Issue, state: VMState | None = None) -> OpcodeResult:
        """Terminate with an error."""
        all_issues = [issue]
        if state is not None:
            all_issues.extend(cls._collect_pending(state))
        return cls(new_states=[], issues=all_issues, terminal=True)


OpcodeHandler = Callable[[dis.Instruction, "VMState", "OpcodeDispatcher"], OpcodeResult]


class OpcodeDispatcher:
    """Dispatches bytecode instructions to registered handlers.
    This class manages a registry of opcode handlers and provides
    the execution context for instruction interpretation.
    Example:
        dispatcher = OpcodeDispatcher()
        @dispatcher.register("LOAD_FAST")
        def handle_load_fast(instr, state, ctx):
            ...
    """

    _global_handlers: dict[str, OpcodeHandler] = {}

    def __init__(self) -> None:
        """Initialize the dispatcher."""
        self._handlers: dict[str, OpcodeHandler] = {}
        self._instructions: list[dis.Instruction] = []
        self._offset_to_index: dict[int, int] = {}
        self._fallback_handler: OpcodeHandler | None = None
        self.cross_function: object | None = None
        self._exception_entries: list[object] = []

    def register(self, *opcodes: str) -> Callable[[OpcodeHandler], OpcodeHandler]:
        """Decorator to register a handler for one or more opcodes.
        Args:
            opcodes: One or more opcode names (e.g., "LOAD_FAST", "STORE_FAST").
        Returns:
            Decorator function.
        Example:
            @dispatcher.register("LOAD_FAST", "LOAD_FAST_CHECK")
            def handle_load(instr, state, ctx):
                ...
        """

        def decorator(handler: OpcodeHandler) -> OpcodeHandler:
            for opcode in opcodes:
                self._handlers[opcode] = handler
            return handler

        return decorator

    def register_handler(self, opcode: str, handler: OpcodeHandler) -> None:
        """Register a handler for an opcode (used by plugins)."""
        self._handlers[opcode] = handler

    @property
    def instructions(self) -> list[dis.Instruction]:
        """Read-only access to current instruction list."""
        return self._instructions

    def set_fallback(self, handler: OpcodeHandler) -> None:
        """Set a fallback handler for unregistered opcodes."""
        self._fallback_handler = handler

    def set_instructions(self, instructions: list[dis.Instruction]) -> None:
        """Set the instruction list for the current function.
        Args:
            instructions: List of disassembled instructions.
        """
        self._instructions = instructions
        self._offset_to_index = {instr.offset: idx for idx, instr in enumerate(instructions)}

    def set_exception_entries(self, entries: list[object]) -> None:
        """Store exception table entries for handler lookup."""
        self._exception_entries = list(entries)

    def find_exception_handler(self, offset: int) -> int | None:
        """Find the exception handler index covering a bytecode offset.

        Returns the instruction index of the handler, or None.
        """
        for entry in self._exception_entries:
            start = getattr(entry, "start", None)
            end = getattr(entry, "end", None)
            target = getattr(entry, "target", None)
            if start is not None and end is not None and target is not None:
                if start <= offset < end:
                    idx = self._offset_to_index.get(target)
                    if idx is not None:
                        return idx

        return None

    def get_instruction(self, index: int) -> dis.Instruction | None:
        """Get instruction by index."""
        if 0 <= index < len(self._instructions):
            return self._instructions[index]
        return None

    def offset_to_index(self, offset: int) -> int | None:
        """Convert bytecode offset to instruction index."""
        return self._offset_to_index.get(offset)

    def dispatch(self, instr: dis.Instruction, state: VMState) -> OpcodeResult:
        """Dispatch an instruction to its handler."""
        handler = self._handlers.get(instr.opname)
        if handler is None:
            handler = OpcodeDispatcher._global_handlers.get(instr.opname)
        if handler is None:
            if self._fallback_handler is not None:
                return self._fallback_handler(instr, state, self)
            raise NotImplementedError(f"Opcode not supported: {instr.opname}")
        return handler(instr, state, self)

    def has_handler(self, opcode: str) -> bool:
        """Check if a handler is registered for an opcode."""
        return opcode in self._handlers or opcode in OpcodeDispatcher._global_handlers

    def registered_opcodes(self) -> set[str]:
        """Get the set of registered opcode names."""
        return set(self._handlers.keys()) | set(OpcodeDispatcher._global_handlers.keys())

    @classmethod
    def register_global(cls, opcode: str, handler: OpcodeHandler) -> None:
        """Register a handler globally for all dispatcher instances."""
        cls._global_handlers[opcode] = handler

    def instruction_count(self) -> int:
        """Get the number of instructions."""
        return len(self._instructions)

    def __repr__(self) -> str:
        return f"OpcodeDispatcher({len(self._handlers)} handlers)"


_global_dispatcher: OpcodeDispatcher | None = None
_global_dispatcher_lock = threading.Lock()


def get_global_dispatcher() -> OpcodeDispatcher:
    """Get or create the global opcode dispatcher.

    Thread-safe via double-checked locking.
    """
    global _global_dispatcher
    if _global_dispatcher is not None:
        return _global_dispatcher
    with _global_dispatcher_lock:
        if _global_dispatcher is None:
            _global_dispatcher = OpcodeDispatcher()
        return _global_dispatcher


def opcode_handler(*opcodes: str) -> Callable[[OpcodeHandler], OpcodeHandler]:
    """Decorator to register an opcode handler globally.
    Handlers registered with this decorator are available to all
    OpcodeDispatcher instances.
    Example:
        @opcode_handler("LOAD_FAST")
        def handle_load_fast(instr, state, ctx):
            ...
    """

    def decorator(handler: OpcodeHandler) -> OpcodeHandler:
        for opcode in opcodes:
            OpcodeDispatcher.register_global(opcode, handler)
        return handler

    return decorator
