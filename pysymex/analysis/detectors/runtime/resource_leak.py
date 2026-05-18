# pysymex: Python Symbolic Execution & Formal Verification
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

from __future__ import annotations

import ast
import dis
from collections.abc import Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.core.state import VMState

import z3
from pysymex.core.solver.engine import get_model
from pysymex.core.types import SymbolicString, SymbolicValue
from pysymex.analysis.detectors.base import Detector, Issue, IssueKind, IsSatFn
from pysymex.analysis.detectors.runtime.division_by_zero import extract_argc


def _resolve_target_name(state: VMState, argc: int) -> str | None:
    """Resolve call target name from stack shape around call arguments."""
    candidate_indices = (len(state.stack) - argc - 2, len(state.stack) - argc - 1)
    for index in candidate_indices:
        if index < 0 or index >= len(state.stack):
            continue
        candidate = state.stack[index]
        candidate_type_name = type(candidate).__name__
        if candidate_type_name == "SymbolicNone":
            continue
        for attr in ("__name__", "__qualname__", "qualname", "name", "origin"):
            value = getattr(candidate, attr, None)
            if isinstance(value, str) and value:
                lowered = value.lower()
                if lowered in {"none", "null", "push_null_none"}:
                    continue
                if not _is_plausible_callable_name(value):
                    continue
                return value
    return None


def _is_plausible_callable_name(name: str) -> bool:
    """Return True when a target-name string looks like a callable identifier."""
    stripped = name.strip()
    if stripped != name or not stripped:
        return False
    for invalid_char in ("'", '"', ",", "(", ")", " "):
        if invalid_char in stripped:
            return False
    return True


def _is_open_target(target_name: str) -> bool:
    """Return True when call target likely opens a resource."""
    lowered = target_name.lower()
    if lowered in {"open", "io.open", "builtins.open"}:
        return True
    return lowered.endswith(".open") or lowered.endswith("_open") or lowered.endswith("open")


def _is_close_target(target_name: str) -> bool:
    """Return True when call target likely closes a resource."""
    lowered = target_name.lower()
    return lowered == "close" or lowered.endswith(".close")


def _extract_literal_string(value: object) -> str | None:
    """Extract literal string payload from concrete/symbolic string values."""
    if isinstance(value, str):
        return value
    if isinstance(value, SymbolicString):
        if z3.is_string_value(value.z3_str):
            return value.z3_str.as_string()
        name_literal = _decode_literal_string_name(value.name)
        if name_literal is not None:
            return name_literal
        return None
    if isinstance(value, SymbolicValue):
        if isinstance(value.value, str):
            return value.value
        if z3.is_string_value(value.z3_str):
            return value.z3_str.as_string()
        name_literal = _decode_literal_string_name(value.name)
        if name_literal is not None:
            return name_literal
        return None
    return None


def _decode_literal_string_name(name: str) -> str | None:
    """Decode repr-style string names used by symbolic constants."""
    stripped = name.strip()
    if len(stripped) < 2:
        return None
    quote_char = stripped[0]
    if quote_char not in {"'", '"'} or stripped[-1] != quote_char:
        return None
    try:
        decoded = ast.literal_eval(stripped)
    except (SyntaxError, ValueError):
        return None
    if isinstance(decoded, str):
        return decoded
    return None


def _looks_like_open_signature(args: Sequence[object]) -> bool:
    """Heuristic for open-like wrappers when direct target names are unavailable."""
    if len(args) < 2:
        return False
    mode_literal = _extract_literal_string(args[1])
    if mode_literal is None:
        return False
    normalized_mode = mode_literal.strip().lower()
    file_modes = {
        "r",
        "w",
        "a",
        "x",
        "rb",
        "wb",
        "ab",
        "xb",
        "r+",
        "w+",
        "a+",
        "rb+",
        "wb+",
        "ab+",
    }
    return normalized_mode in file_modes


class ResourceLeakDetector(Detector):
    """Detect potential unclosed resources using path-local open-resource counts."""

    name = "resource-leak"
    description = "Detects unclosed resources (files, connections)"
    issue_kind = IssueKind.RESOURCE_LEAK
    relevant_opcodes = frozenset(
        {
            "CALL",
            "CALL_FUNCTION",
            "CALL_METHOD",
            "CALL_KW",
            "BEFORE_WITH",
            "RETURN_VALUE",
            "RETURN_CONST",
            "RAISE_VARARGS",
        }
    )

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Track open/close calls and report leaks on function exits."""
        if instruction.opname not in self.relevant_opcodes:
            return None

        if instruction.opname in {"CALL", "CALL_FUNCTION", "CALL_METHOD", "CALL_KW"}:
            argc = extract_argc(instruction)
            target_name = _resolve_target_name(state, argc)
            if target_name is None:
                if argc > 0 and len(state.stack) >= argc:
                    args = list(state.stack[-argc:])
                    if _looks_like_open_signature(args):
                        state.open_resources += 1
                return None
            if _is_open_target(target_name):
                state.open_resources += 1
            elif _is_close_target(target_name) and state.open_resources > 0:
                state.open_resources -= 1
            return None

        if instruction.opname == "BEFORE_WITH":
            # `with open(...)` transfers cleanup responsibility to the context manager.
            if state.open_resources > 0:
                state.open_resources -= 1
            return None

        if instruction.opname in {"RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS"}:
            # Only report at root-function exits. Nested helper returns can
            # legitimately pass open handles back to the caller for closure.
            if state.call_stack:
                return None
            if state.open_resources <= 0:
                return None
            constraints = list(state.path_constraints)
            if not _solver_check(constraints):
                return None
            leaked_count = state.open_resources
            state.open_resources = 0
            return Issue(
                kind=IssueKind.RESOURCE_LEAK,
                message=f"Potential resource leak: {leaked_count} unclosed resources",
                constraints=constraints,
                model=get_model(constraints),
                pc=state.pc,
            )
        return None
