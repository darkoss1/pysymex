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

"""Detect function parameters that are never loaded in the function body."""

from __future__ import annotations

from types import CodeType

from pysymex.analysis.static.dead_code.bytecode_helpers import (
    as_object_tuple,
    cached_get_instructions,
)
from pysymex.analysis.static.dead_code.types import DeadCode, DeadCodeKind
from pysymex.analysis.static.dead_code.variables import UnusedVariableDetector


class UnusedParameterDetector:
    """Detects function parameters that are never used."""

    IGNORED_NAMES: set[str] = {"self", "cls", "_", "*args", "**kwargs"}

    @staticmethod
    def _is_stub_body(code: CodeType) -> bool:
        """Check if a function body is a stub."""
        for instr in cached_get_instructions(code):
            if instr.opname in {"RESUME", "NOP", "POP_TOP", "RETURN_VALUE", "PUSH_NULL", "PRECALL"}:
                continue
            if instr.opname == "RETURN_CONST" and instr.argval is None:
                continue
            if instr.opname == "LOAD_CONST" and instr.argval in (None, Ellipsis):
                continue
            if (
                instr.opname in {"LOAD_GLOBAL", "LOAD_NAME"}
                and instr.argval == "NotImplementedError"
            ):
                continue
            if instr.opname in {"CALL", "CALL_FUNCTION", "RAISE_VARARGS"}:
                continue
            return False
        return True

    def detect(self, code: CodeType, file_path: str = "<unknown>") -> list[DeadCode]:
        """Compare declared parameters against loaded locals in bytecode."""
        dead_code: list[DeadCode] = []
        if self._is_stub_body(code):
            return dead_code
        params = set(code.co_varnames[: code.co_argcount])
        used: set[str] = set()
        for instr in cached_get_instructions(code):
            if instr.opname in {
                "LOAD_FAST",
                "LOAD_DEREF",
                "LOAD_NAME",
                "LOAD_GLOBAL",
                "LOAD_CLASSDEREF",
                "LOAD_FAST_AND_CLEAR",
            }:
                used.add(str(instr.argval))
            elif instr.opname in {"LOAD_FAST_LOAD_FAST", "STORE_FAST_LOAD_FAST"}:
                for name_obj in as_object_tuple(instr.argval):
                    used.add(str(name_obj))

        nested_uses = UnusedVariableDetector.collect_nested_uses(code)
        for param in params:
            if param in self.IGNORED_NAMES:
                continue
            if param.startswith("_"):
                continue
            if param not in used and param not in nested_uses:
                dead_code.append(
                    DeadCode(
                        kind=DeadCodeKind.UNUSED_PARAMETER,
                        file=file_path,
                        line=code.co_firstlineno,
                        name=param,
                        message=f"Parameter '{param}' is never used",
                        confidence=0.9,
                    )
                )
        return dead_code


__all__ = ["UnusedParameterDetector"]
