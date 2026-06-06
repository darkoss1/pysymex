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

"""Detect reference cycles that prevent deterministic resource cleanup."""

from __future__ import annotations

from types import CodeType

from pysymex.core.bytecode import get_starts_line
from pysymex.analysis.domains.resources.usage import ObjectNode, ResourceKind, ResourceWarning
from pysymex.core.cache import get_instructions as cached_get_instructions


class ReferenceCycleDetector:
    """Detects potential reference cycles that could cause memory leaks."""

    def detect(
        self,
        code: CodeType,
        file_path: str = "<unknown>",
    ) -> list[ResourceWarning]:
        """Detect potential reference cycles."""
        warnings: list[ResourceWarning] = []
        instructions = cached_get_instructions(code)
        current_line = code.co_firstlineno
        self_attrs: dict[str, int] = {}
        loading_self = False
        for instr in instructions:
            line = get_starts_line(instr)
            if line is not None:
                current_line = line
            opname = instr.opname
            arg = instr.argval
            if opname in {"LOAD_FAST", "LOAD_NAME"} and str(arg) == "self":
                loading_self = True
            elif opname == "STORE_ATTR" and loading_self:
                self_attrs[str(arg)] = current_line
                loading_self = False
            elif opname in {"LOAD_ATTR", "LOAD_METHOD"} and loading_self:
                loading_self = False
            else:
                loading_self = False
        if code.co_name == "__init__" and "parent" in self_attrs and "children" in self_attrs:
            warnings.append(
                ResourceWarning(
                    kind="POTENTIAL_REFERENCE_CYCLE",
                    file=file_path,
                    line=self_attrs.get("parent", code.co_firstlineno) or 0,
                    resource_kind=ResourceKind.CONTEXT_MANAGER,
                    resource_name="parent-child",
                    message=(
                        "Potential reference cycle: object has both 'parent' "
                        "and 'children' attributes - ensure proper cleanup or use weakref"
                    ),
                    severity="warning",
                )
            )
        return warnings


__all__ = ["ObjectNode", "ReferenceCycleDetector"]
