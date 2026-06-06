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

"""Analyse context-manager (``with`` statement) resource usage for leak detection."""

from __future__ import annotations

from types import CodeType

from pysymex.core.bytecode import get_starts_line
from pysymex.analysis.domains.resources.usage import (
    ResourceKind,
    ResourceWarning,
    extract_call_argc,
    is_counted_resource_call,
    is_zero_arg_builtin_open,
)
from pysymex.core.cache import get_instructions as cached_get_instructions


class ContextManagerAnalyzer:
    """Analyzes context manager usage patterns."""

    def analyze(
        self,
        code: CodeType,
        file_path: str = "<unknown>",
    ) -> list[ResourceWarning]:
        """Analyze context manager usage."""
        warnings: list[ResourceWarning] = []
        instructions = cached_get_instructions(code)
        current_line = code.co_firstlineno
        open_without_with: list[tuple[str, int]] = []
        pending_open_line: int | None = None
        for i, instr in enumerate(instructions):
            line = get_starts_line(instr)
            if line is not None:
                current_line = line
            opname = instr.opname
            arg = instr.argval
            if opname in {"LOAD_GLOBAL", "LOAD_NAME"} and str(arg) == "open":
                pending_open_line = current_line
            elif is_counted_resource_call(instr) and pending_open_line is not None:
                argc = extract_call_argc(instr)
                if is_zero_arg_builtin_open("open", argc):
                    pending_open_line = None
                    continue
                found_with = False
                for j in range(i + 1, min(i + 10, len(instructions))):
                    if instructions[j].opname == "BEFORE_WITH":
                        found_with = True
                        break
                    if instructions[j].opname in {"STORE_FAST", "STORE_NAME"}:
                        break
                if not found_with:
                    open_without_with.append(("open", pending_open_line))
                pending_open_line = None
        for func, line in open_without_with:
            warnings.append(
                ResourceWarning(
                    kind="MISSING_CONTEXT_MANAGER",
                    file=file_path,
                    line=line,
                    resource_kind=ResourceKind.FILE_HANDLE,
                    resource_name="file",
                    message=f"'{func}()' should be used with 'with' statement",
                    severity="warning",
                )
            )
        return warnings


__all__ = ["ContextManagerAnalyzer"]
