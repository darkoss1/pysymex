"""Exception handler awareness for reducing false positives.

This module detects when code is inside exception handlers to avoid
reporting unreachable code or expected error conditions.

"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

import ast
import dis
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum, auto

from pysymex.core.instruction_cache import get_instructions as _cached_get_instructions


class ExceptionHandlerType(Enum):
    """Types of exception handlers."""

    EXCEPT = auto()
    EXCEPT_TYPE = auto()
    EXCEPT_AS = auto()
    FINALLY = auto()
    ELSE = auto()


@dataclass
class ExceptionHandlerInfo:
    """Information about an exception handler block."""

    handler_type: ExceptionHandlerType
    start_pc: int
    end_pc: int
    exception_types: list[str] = field(default_factory=list[str])
    exception_var: str | None = None
    nesting_depth: int = 0


@dataclass
class ExceptionHandlerState:
    """Tracks exception handler context."""

    active_handlers: list[ExceptionHandlerInfo] = field(default_factory=list[ExceptionHandlerInfo])

    all_handlers: list[ExceptionHandlerInfo] = field(default_factory=list[ExceptionHandlerInfo])

    def enter_handler(self, handler: ExceptionHandlerInfo) -> None:
        """Enter an exception handler block."""
        handler.nesting_depth = len(self.active_handlers)
        self.active_handlers.append(handler)

    def exit_handler(self) -> ExceptionHandlerInfo | None:
        """Exit the current exception handler."""
        if self.active_handlers:
            return self.active_handlers.pop()
        return None

    def is_in_handler(self) -> bool:
        """Check if currently inside an exception handler."""
        return len(self.active_handlers) > 0

    def current_handler(self) -> ExceptionHandlerInfo | None:
        """Get the innermost active handler."""
        if self.active_handlers:
            return self.active_handlers[-1]
        return None

    def is_in_finally(self) -> bool:
        """Check if currently inside a finally block."""
        return any(h.handler_type == ExceptionHandlerType.FINALLY for h in self.active_handlers)

    def copy(self) -> ExceptionHandlerState:
        """Create a copy of the state."""
        return ExceptionHandlerState(
            active_handlers=list(self.active_handlers),
            all_handlers=list(self.all_handlers),
        )


class ExceptionHandlerAnalyzer:
    """Analyzes code to detect exception handler blocks."""

    def __init__(self) -> None:
        """Initialize the analyzer."""
        self._state = ExceptionHandlerState()
        self._handler_ranges: dict[int, tuple[int, int]] = {}

    def analyze_bytecode(self, code: object) -> list[ExceptionHandlerInfo]:
        """Extract exception handlers from bytecode.

        Args:
            code: The code object to analyze

        Returns:
            List of detected exception handlers
        """
        handlers: list[ExceptionHandlerInfo] = []

        if hasattr(code, "co_exceptiontable") and code.co_exceptiontable:
            handlers.extend(self._parse_exception_table(code))

        instructions = _cached_get_instructions(code)
        handlers.extend(self._detect_handler_patterns(instructions))

        self._state.all_handlers = handlers
        return handlers

    def _parse_exception_table(self, code: object) -> list[ExceptionHandlerInfo]:
        """Parse the exception table from Python 3.11+ code objects."""
        handlers: list[ExceptionHandlerInfo] = []

        try:
            table = code.co_exceptiontable
            if not table:
                return handlers

            instructions = _cached_get_instructions(code)

            for i, instr in enumerate(instructions):
                if instr.opname == "PUSH_EXC_INFO":
                    start_pc = instr.offset
                    end_pc = self._find_handler_end(instructions, i)
                    handlers.append(
                        ExceptionHandlerInfo(
                            handler_type=ExceptionHandlerType.EXCEPT,
                            start_pc=start_pc,
                            end_pc=end_pc,
                        )
                    )

        except (ValueError, IndexError):
            pass  # Used as expected type-check or feature fallback

        return handlers

    def _detect_handler_patterns(
        self,
        instructions: Sequence[dis.Instruction],
    ) -> list[ExceptionHandlerInfo]:
        """Detect exception handler patterns in bytecode."""
        handlers: list[ExceptionHandlerInfo] = []

        for i, instr in enumerate(instructions):
            if instr.opname in ("SETUP_FINALLY", "SETUP_EXCEPT"):
                target = instr.argval
                handlers.append(
                    ExceptionHandlerInfo(
                        handler_type=(
                            ExceptionHandlerType.FINALLY
                            if "FINALLY" in instr.opname
                            else ExceptionHandlerType.EXCEPT
                        ),
                        start_pc=instr.offset,
                        end_pc=target,
                    )
                )

            elif instr.opname == "PUSH_EXC_INFO":
                start_pc = instr.offset
                end_pc = self._find_handler_end(instructions, i)
                handlers.append(
                    ExceptionHandlerInfo(
                        handler_type=ExceptionHandlerType.EXCEPT,
                        start_pc=start_pc,
                        end_pc=end_pc,
                    )
                )

        return handlers

    def _find_handler_end(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
    ) -> int:
        """Find the end of an exception handler block."""
        for i in range(start_idx + 1, len(instructions)):
            instr = instructions[i]
            if instr.opname in ("POP_EXCEPT", "RERAISE", "END_FINALLY"):
                return instr.offset
            if instr.opname in ("RETURN_VALUE", "RETURN_CONST"):
                return instr.offset

        return instructions[-1].offset if instructions else 0

    def analyze_source(self, source_code: str) -> list[ExceptionHandlerInfo]:
        """Extract exception handlers from source code.

        Args:
            source_code: The source code to analyze

        Returns:
            List of detected exception handlers
        """
        try:
            tree = ast.parse(source_code)
            return self._visit_ast(tree)
        except SyntaxError:
            return []

    def _visit_ast(self, node: ast.AST, depth: int = 0) -> list[ExceptionHandlerInfo]:
        """Visit AST nodes to find exception handlers."""
        handlers: list[ExceptionHandlerInfo] = []

        for child in ast.walk(node):
            if isinstance(child, ast.Try):
                for handler in child.handlers:
                    exc_types = []
                    exc_var = None

                    if handler.type:
                        if isinstance(handler.type, ast.Name):
                            exc_types = [handler.type.id]
                        elif isinstance(handler.type, ast.Tuple):
                            exc_types = [
                                elt.id for elt in handler.type.elts if isinstance(elt, ast.Name)
                            ]

                    if handler.name:
                        exc_var = handler.name
                        handler_type = ExceptionHandlerType.EXCEPT_AS
                    elif exc_types:
                        handler_type = ExceptionHandlerType.EXCEPT_TYPE
                    else:
                        handler_type = ExceptionHandlerType.EXCEPT

                    handlers.append(
                        ExceptionHandlerInfo(
                            handler_type=handler_type,
                            start_pc=getattr(handler, "lineno", 0),
                            end_pc=getattr(handler, "end_lineno", 0),
                            exception_types=exc_types,
                            exception_var=exc_var,
                            nesting_depth=depth,
                        )
                    )

                if child.finalbody:
                    handlers.append(
                        ExceptionHandlerInfo(
                            handler_type=ExceptionHandlerType.FINALLY,
                            start_pc=child.finalbody[0].lineno if child.finalbody else child.lineno,
                            end_pc=(
                                child.finalbody[-1].end_lineno or 0
                                if child.finalbody
                                else child.lineno
                            ),
                            nesting_depth=depth,
                        )
                    )

                if child.orelse:
                    handlers.append(
                        ExceptionHandlerInfo(
                            handler_type=ExceptionHandlerType.ELSE,
                            start_pc=child.orelse[0].lineno if child.orelse else child.lineno,
                            end_pc=(
                                (child.orelse[-1].end_lineno or 0) if child.orelse else child.lineno
                            ),
                            nesting_depth=depth,
                        )
                    )

        return handlers

    def is_pc_in_handler(self, pc: int) -> bool:
        """Check if a program counter is inside an exception handler.

        Args:
            pc: The program counter to check

        Returns:
            True if inside an exception handler
        """
        for handler in self._state.all_handlers:
            if handler.start_pc <= pc <= handler.end_pc:
                return True
        return False

    def is_line_in_handler(self, line_number: int) -> bool:
        """Check if a line number is inside an exception handler.

        Args:
            line_number: The line number to check

        Returns:
            True if inside an exception handler
        """
        for handler in self._state.all_handlers:
            if handler.start_pc <= line_number <= handler.end_pc:
                return True
        return False

    def get_handler_at(self, pc: int) -> ExceptionHandlerInfo | None:
        """Get the exception handler at a given PC.

        Args:
            pc: The program counter

        Returns:
            The handler info or None
        """
        for handler in self._state.all_handlers:
            if handler.start_pc <= pc <= handler.end_pc:
                return handler
        return None

    def get_state(self) -> ExceptionHandlerState:
        """Get the current state."""
        return self._state

    def set_state(self, state: ExceptionHandlerState) -> None:
        """Set the current state."""
        self._state = state


def should_skip_issue_in_handler(
    line_number: int | None,
    issue_kind: str,
    handlers: list[ExceptionHandlerInfo],
) -> bool:
    """Determine if an issue should be skipped because it's in an expected handler.

    Args:
        line_number: Line number of the issue
        issue_kind: Kind of issue (e.g., "UNREACHABLE_CODE")
        handlers: List of exception handlers

    Returns:
        True if the issue should be skipped
    """
    if line_number is None:
        return False

    skip_in_handler = {
        "UNREACHABLE_CODE",
        "DEAD_CODE",
    }

    if issue_kind not in skip_in_handler:
        return False

    for handler in handlers:
        if handler.start_pc <= line_number <= handler.end_pc:
            return True

    return False
