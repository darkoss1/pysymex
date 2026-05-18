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

from typing import TYPE_CHECKING

from pysymex.analysis.detectors.base import Detector, Issue, IssueKind, DisInstruction, IsSatFn

if TYPE_CHECKING:
    from pysymex.core.state import VMState

from .helpers import resolve_target_name, get_named_value_name


def _extract_argc(instruction: DisInstruction) -> int:
    """Extract argument count from a call-like instruction."""
    if isinstance(instruction.argval, int):
        return instruction.argval
    if isinstance(instruction.arg, int):
        return instruction.arg
    return 0


def _extract_candidate_name(value: object) -> str | None:
    """Return the best-effort symbolic/display name for a stack value."""
    named = get_named_value_name(value)
    if named is not None and named:
        return named
    for attr in ("__name__", "__qualname__", "qualname", "name", "origin"):
        attr_value = getattr(value, attr, None)
        if isinstance(attr_value, str) and attr_value:
            return attr_value
    return None


def _is_close_target_name(target_name: str) -> bool:
    """Return True when a call target looks like a close/release call."""
    lowered = target_name.lower()
    return lowered == "close" or lowered.endswith(".close")


def _resolve_receiver_name(state: VMState, argc: int, target_name: str) -> str | None:
    """Resolve receiver name from stack layout around a method call."""
    candidate_indices = (len(state.stack) - argc - 1, len(state.stack) - argc - 2)
    target_prefix: str | None = None
    if target_name.lower().endswith(".close"):
        target_prefix = target_name[: -len(".close")]
    for index in candidate_indices:
        if index < 0 or index >= len(state.stack):
            continue
        candidate = state.stack[index]
        candidate_name = get_named_value_name(candidate)
        if candidate_name is None:
            continue
        if target_prefix is not None and candidate_name != target_prefix:
            continue
        return candidate_name
    return None


class UseAfterFreeDetector(Detector):
    """Detects use-after-free patterns (e.g. using a closed file handle).

    Uses path-local state in VMState.freed_vars to ensure isolation
    between different execution paths.
    """

    name = "use-after-free"
    description = "Detects use of released resources"
    issue_kind = IssueKind.ATTRIBUTE_ERROR
    relevant_opcodes = frozenset(
        {"CALL", "CALL_FUNCTION", "CALL_METHOD", "CALL_KW", "LOAD_METHOD", "LOAD_ATTR"}
    )

    def check(
        self,
        state: VMState,
        instruction: DisInstruction,
        is_satisfiable_fn: IsSatFn,
    ) -> Issue | None:
        """Check for use of freed/closed resources."""
        _ = is_satisfiable_fn
        if instruction.opname in ("CALL", "CALL_FUNCTION", "CALL_METHOD", "CALL_KW"):
            argc = _extract_argc(instruction)
            call_candidates = (
                len(state.stack) - argc - 1,
                len(state.stack) - argc - 2,
            )
            candidate_names: list[str] = []
            for index in call_candidates:
                if index < 0 or index >= len(state.stack):
                    continue
                name = _extract_candidate_name(state.stack[index])
                if name is not None:
                    candidate_names.append(name)

            resolved_target = resolve_target_name(state, argc)
            if resolved_target is not None:
                candidate_names.append(resolved_target)

            close_targets = tuple(name for name in candidate_names if _is_close_target_name(name))
            if close_targets:
                receiver_name: str | None = None
                for close_target in close_targets:
                    receiver_name = _resolve_receiver_name(state, argc, close_target)
                    if receiver_name is not None:
                        break
                if receiver_name is not None:
                    state.freed_vars.add(receiver_name)
        elif instruction.opname in ("LOAD_METHOD", "LOAD_ATTR"):
            if state.stack:
                top = state.peek()
                top_name = get_named_value_name(top)
                if top_name is not None and top_name in state.freed_vars:
                    return Issue(
                        kind=IssueKind.ATTRIBUTE_ERROR,
                        message=f"Use of closed/freed resource: {top_name}",
                        pc=state.pc,
                    )
        return None
