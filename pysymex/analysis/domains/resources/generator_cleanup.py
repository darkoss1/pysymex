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

"""Detect generators that acquire resources but lack proper cleanup paths."""

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


class GeneratorCleanupAnalyzer:
    """Analyzes generator cleanup patterns."""

    def analyze(
        self,
        code: CodeType,
        file_path: str = "<unknown>",
    ) -> list[ResourceWarning]:
        """Check for generator cleanup issues."""
        warnings: list[ResourceWarning] = []
        is_generator = bool(code.co_flags & 0x20)
        if not is_generator:
            return warnings
        instructions = cached_get_instructions(code)
        current_line = code.co_firstlineno
        has_finally = False
        has_close_check = False
        has_resource_open = False
        resource_line = 0
        pending_open_line: int | None = None
        for instr in instructions:
            line = get_starts_line(instr)
            if line is not None:
                current_line = line
            opname = instr.opname
            arg = instr.argval
            if opname == "SETUP_FINALLY":
                has_finally = True
            if opname == "LOAD_GLOBAL" and str(arg) == "GeneratorExit":
                has_close_check = True
            if opname in {"LOAD_GLOBAL", "LOAD_NAME"} and str(arg) == "open":
                pending_open_line = current_line
                continue
            if is_counted_resource_call(instr) and pending_open_line is not None:
                argc = extract_call_argc(instr)
                if is_zero_arg_builtin_open("open", argc):
                    pending_open_line = None
                    continue
                has_resource_open = True
                resource_line = pending_open_line
                pending_open_line = None
        if has_resource_open and not has_finally and not has_close_check:
            warnings.append(
                ResourceWarning(
                    kind="GENERATOR_RESOURCE_LEAK",
                    file=file_path,
                    line=resource_line,
                    resource_kind=ResourceKind.GENERATOR,
                    resource_name="generator",
                    message=(
                        "Generator opens resources but has no cleanup code. "
                        "If generator is not fully consumed, resources may leak."
                    ),
                    severity="warning",
                )
            )
        return warnings


__all__ = ["GeneratorCleanupAnalyzer"]
