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

"""Resource Leak detection module.

Tracks file handles, sockets, and other resources to check if they are closed on function
exit paths.

Bug Class Detected:
    Resource Leak.

Required Evidence:
    A function exit (e.g. RETURN_VALUE) where the VMState has a non-zero count of open resources.

Issue Kinds:
    IssueKind.RESOURCE_LEAK
"""

from __future__ import annotations

import ast
import dis
from collections.abc import Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState

import z3
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.analysis.detectors.detector.contract import Detector
from pysymex.analysis.detectors.detector.types import IsSatFn, Issue, IssueKind
from pysymex.analysis.detectors.calls import extract_argc, resolve_call_target_name
from pysymex.analysis.detectors.feasibility import get_model_if_satisfiable
from pysymex.analysis.domains.resources.usage import (
    FILE_OPEN_MODES,
    RESOURCE_CLOSERS,
    RESOURCE_OPENERS,
    is_zero_arg_builtin_open,
)


def _resolve_target_name(state: VMState, argc: int) -> str | None:
    """Resolve call target name from stack shape around call arguments."""
    return resolve_call_target_name(state, argc, require_plausible_callable=True)


def _is_open_target(target_name: str) -> bool:
    """Return True when call target likely opens a resource."""
    lowered = target_name.lower()
    opener_names = {name.lower() for name in RESOURCE_OPENERS}
    if lowered in opener_names or any(lowered.endswith(f".{name}") for name in opener_names):
        return True
    return lowered.endswith(".open") or lowered.endswith("_open") or lowered.endswith("open")


def _is_close_target(target_name: str) -> bool:
    """Return True when call target likely closes a resource."""
    lowered = target_name.lower()
    closer_names = {name.lower() for name in RESOURCE_CLOSERS}
    return lowered in closer_names or any(lowered.endswith(f".{name}") for name in closer_names)


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
    return normalized_mode in FILE_OPEN_MODES


class ResourceLeakDetector(Detector):
    """Detect potentially unclosed resources on function-exit paths.

    Bug class:
        Unclosed file handles, sockets, database connections, and
        other open resources not released before ``RETURN_VALUE``,
        ``RETURN_CONST``, or ``RAISE_VARARGS``.

    Evidence:
        A path-local ``open_resources`` counter is non-zero at a
        root-function exit and the current path constraints are satisfiable.

    Issue kind:
        ``IssueKind.RESOURCE_LEAK``.

    Known limitations:
        The open-resource counter is path-local and does not track
        which specific handle is leaked.  Closing a resource via a
        non-standard helper that is not in ``RESOURCE_CLOSERS`` will
        inflate the count and produce a false positive.  ``BEFORE_WITH``
        decrements the counter to credit ``with``-statement cleanup.
    """

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
        """Track open/close calls and report any unclosed resource on function exit.

        Increments ``state.open_resources`` on opener calls, decrements it
        on closer calls and ``BEFORE_WITH``.  On exit opcodes, checks whether
        the path is feasible and reports a leak if the counter is positive.
        """
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
                if is_zero_arg_builtin_open(target_name, argc):
                    return None
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
            model = get_model_if_satisfiable(constraints, _solver_check)
            if model is None:
                return None
            leaked_count = state.open_resources
            state.open_resources = 0
            return Issue(
                kind=IssueKind.RESOURCE_LEAK,
                message=f"Potential resource leak: {leaked_count} unclosed resources",
                constraints=constraints,
                model=model,
                pc=state.pc,
            )
        return None
