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

"""Detect resource leaks from bytecode-level open/acquire patterns."""

from __future__ import annotations

import dis
from collections.abc import Sequence
from types import CodeType

from pysymex.core.bytecode import get_starts_line
from pysymex.analysis.domains.resources.usage import (
    RESOURCE_CLOSERS,
    RESOURCE_OPENERS,
    Resource,
    ResourceState,
    ResourceWarning,
    extract_call_argc,
    is_counted_resource_call,
    is_zero_arg_builtin_open,
)
from pysymex.core.cache import get_instructions as cached_get_instructions


class ResourceLeakAnalyzer:
    """Detects resource leaks by tracking open/close operations."""

    def __init__(self) -> None:
        self.resources: dict[str, Resource] = {}
        self.warnings: list[ResourceWarning] = []
        self.context_stack: list[str] = []

    def detect(
        self,
        code: CodeType,
        file_path: str = "<unknown>",
    ) -> list[ResourceWarning]:
        """Detect resource leaks in function."""
        self.resources.clear()
        self.warnings.clear()
        self.context_stack.clear()
        reported_leaks: set[str] = set()
        instructions = cached_get_instructions(code)
        current_line = code.co_firstlineno
        call_stack: list[str] = []
        pending_store: str | None = None
        for i, instr in enumerate(instructions):
            line = get_starts_line(instr)
            if line is not None:
                current_line = line
            opname = instr.opname
            arg = instr.argval
            if opname in {"LOAD_GLOBAL", "LOAD_NAME"}:
                call_stack.append(str(arg))
            elif opname in {"LOAD_ATTR", "LOAD_METHOD"}:
                self._handle_attribute_load(instructions, i, str(arg), current_line, call_stack)
            elif is_counted_resource_call(instr):
                pending_store = self._pending_resource_opener(call_stack, extract_call_argc(instr))
            elif opname in {"STORE_FAST", "STORE_NAME"}:
                pending_store = self._handle_store(
                    str(arg), pending_store, current_line, instr.offset
                )
            elif opname == "BEFORE_WITH":
                self.context_stack.append("context")
            elif opname == "WITH_CLEANUP_START":
                if self.context_stack:
                    self.context_stack.pop()
            elif opname in {"RETURN_VALUE", "RETURN_CONST"}:
                self._check_leaks_at_exit(file_path, current_line, reported_leaks)
        self._check_leaks_at_exit(file_path, current_line, reported_leaks)
        return self.warnings

    def _handle_attribute_load(
        self,
        instructions: Sequence[dis.Instruction],
        index: int,
        arg: str,
        current_line: int,
        call_stack: list[str],
    ) -> None:
        if arg in RESOURCE_CLOSERS and index > 0:
            prev = instructions[index - 1]
            if prev.opname in {"LOAD_FAST", "LOAD_NAME"}:
                var_name = str(prev.argval)
                if var_name in self.resources:
                    self.resources[var_name].state = ResourceState.CLOSED
                    self.resources[var_name].close_line = current_line
        if call_stack:
            call_stack[-1] = f"{call_stack[-1]}.{arg}"
        else:
            call_stack.append(arg)

    @staticmethod
    def _pending_resource_opener(call_stack: list[str], argc: int) -> str | None:
        if not call_stack:
            return None
        func_name = call_stack.pop()
        for pattern in RESOURCE_OPENERS.keys():
            if func_name.endswith(pattern) or func_name == pattern:
                if is_zero_arg_builtin_open(func_name, argc):
                    return None
                return func_name
        return None

    def _handle_store(
        self,
        var_name: str,
        pending_store: str | None,
        current_line: int,
        offset: int,
    ) -> str | None:
        if not pending_store:
            return None
        for pattern, kind in RESOURCE_OPENERS.items():
            if pending_store.endswith(pattern) or pending_store == pattern:
                self.resources[var_name] = Resource(
                    kind=kind,
                    name=var_name,
                    open_line=current_line,
                    open_pc=offset,
                    in_context_manager=bool(self.context_stack),
                )
                break
        return None

    def _check_leaks_at_exit(
        self,
        file_path: str,
        line: int,
        reported: set[str] | None = None,
    ) -> None:
        """Check for resource leaks at function exit."""
        for name, resource in self.resources.items():
            if not resource.is_leaked():
                continue
            if reported is not None:
                if name in reported:
                    continue
                reported.add(name)
            self.warnings.append(
                ResourceWarning(
                    kind="RESOURCE_LEAK",
                    file=file_path,
                    line=resource.open_line,
                    resource_kind=resource.kind,
                    resource_name=name,
                    message=(
                        f"Resource '{name}' ({resource.kind.name}) opened on line "
                        f"{resource.open_line} may not be closed"
                    ),
                )
            )


__all__ = ["ResourceLeakAnalyzer"]
