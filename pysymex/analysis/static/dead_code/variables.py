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

"""Detect local variables that are stored but never loaded."""

from __future__ import annotations

from collections import defaultdict
from types import CodeType
from typing import cast

from pysymex.analysis.static.dead_code.bytecode_helpers import (
    as_object_tuple,
    cached_get_instructions,
)
from pysymex.analysis.static.dead_code.types import DeadCode, DeadCodeKind


class UnusedVariableDetector:
    """Detects variables assigned but never read."""

    IGNORED_NAMES: set[str] = {"_", "__", "___"}

    def detect(self, code: CodeType, file_path: str = "<unknown>") -> list[DeadCode]:
        """Compare STORE_FAST/STORE_NAME targets against LOAD_FAST/LOAD_NAME uses."""
        dead_code: list[DeadCode] = []
        assignments: dict[str, list[tuple[int, int]]] = defaultdict(list)
        uses: set[str] = set()
        current_line = code.co_firstlineno
        for instr in cached_get_instructions(code):
            if instr.starts_line and type(instr.starts_line) is int:
                current_line = instr.starts_line
            opname = instr.opname
            arg = instr.argval
            if opname in {"STORE_FAST", "STORE_NAME", "STORE_DEREF"}:
                name = str(arg)
                if name not in self.IGNORED_NAMES:
                    assignments[name].append((current_line, instr.offset))
            elif opname in {
                "LOAD_FAST",
                "LOAD_NAME",
                "LOAD_DEREF",
                "LOAD_GLOBAL",
                "LOAD_FAST_AND_CLEAR",
                "DELETE_FAST",
                "DELETE_NAME",
            }:
                uses.add(str(arg))
            elif opname == "STORE_FAST_LOAD_FAST" and isinstance(arg, tuple):
                sname, lname = cast("tuple[object, ...]", arg)
                if str(sname) not in self.IGNORED_NAMES:
                    assignments[str(sname)].append((current_line, instr.offset))
                uses.add(str(lname))
            elif opname == "STORE_FAST_STORE_FAST" and isinstance(arg, tuple):
                for name_obj in cast("tuple[object, ...]", arg):
                    if str(name_obj) not in self.IGNORED_NAMES:
                        assignments[str(name_obj)].append((current_line, instr.offset))
            elif opname == "LOAD_FAST_LOAD_FAST" and isinstance(arg, tuple):
                for name_obj in cast("tuple[object, ...]", arg):
                    uses.add(str(name_obj))

        nested_uses = self._collect_nested_uses(code)
        for name, assign_locs in assignments.items():
            if name in uses or name in nested_uses:
                continue
            if name in code.co_varnames[: code.co_argcount]:
                continue
            if name.startswith("__") and name.endswith("__"):
                continue
            for line, pc in assign_locs:
                dead_code.append(
                    DeadCode(
                        kind=DeadCodeKind.UNUSED_VARIABLE,
                        file=file_path,
                        line=line,
                        name=name,
                        pc=pc,
                        message=f"Variable '{name}' is assigned but never used",
                    )
                )
        return dead_code

    @staticmethod
    def _collect_nested_uses(code: CodeType) -> set[str]:
        """Collect all variable names referenced in nested code objects."""
        uses: set[str] = set()
        for const in code.co_consts:
            if hasattr(const, "co_code"):
                for instr in cached_get_instructions(const):
                    if instr.opname in {
                        "LOAD_FAST",
                        "LOAD_NAME",
                        "LOAD_DEREF",
                        "LOAD_GLOBAL",
                        "LOAD_CLASSDEREF",
                        "LOAD_FAST_AND_CLEAR",
                    }:
                        uses.add(str(instr.argval))
                    elif instr.opname in {"LOAD_FAST_LOAD_FAST", "STORE_FAST_LOAD_FAST"}:
                        for name_obj in as_object_tuple(instr.argval):
                            uses.add(str(name_obj))
                uses.update(UnusedVariableDetector._collect_nested_uses(const))
        for const in code.co_consts:
            if hasattr(const, "co_code"):
                uses.update(const.co_freevars)
        return uses

    @staticmethod
    def collect_nested_uses(code: CodeType) -> set[str]:
        """Public wrapper for nested-use collection."""
        return UnusedVariableDetector._collect_nested_uses(code)


__all__ = ["UnusedVariableDetector"]
