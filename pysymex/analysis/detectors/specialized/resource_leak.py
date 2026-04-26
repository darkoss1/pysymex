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


from .helpers import resolve_target_name, HasName


def get_named_value_name(value: object) -> str | None:
    """Return ``value.name`` only when statically and dynamically safe."""
    if isinstance(value, HasName):
        return value.name
    return None


def resolve_target_name(state: VMState, argc: int) -> str | None:
    """Resolve target name."""
    candidate_indices = [len(state.stack) - argc - 1, len(state.stack) - argc - 2]
    for index in candidate_indices:
        if index < 0 or index >= len(state.stack):
            continue
        candidate = state.stack[index]
        for attr in ("qualname", "name", "origin"):
            value = getattr(candidate, attr, None)
            if isinstance(value, str) and value:
                return value
    return None


class ResourceLeakDetector(Detector):
    """Detects potential resource leaks (unclosed files, connections, etc.)."""

    name = "resource-leak"
    description = "Detects potential resource leaks"
    issue_kind = IssueKind.RESOURCE_LEAK
    relevant_opcodes = frozenset({"CALL", "CALL_FUNCTION", "RETURN_VALUE", "RETURN_CONST"})

    def __init__(self) -> None:
        self._open_resources: int = 0

    def check(
        self,
        state: VMState,
        instruction: DisInstruction,
        is_satisfiable_fn: IsSatFn,
    ) -> Issue | None:
        """Check for resource leaks."""
        if instruction.opname in ("CALL", "CALL_FUNCTION"):
            argc: int = (
                instruction.argval if instruction.argval is not None else (instruction.arg or 0)
            )
            target = resolve_target_name(state, argc)
            if target == "open":
                self._open_resources += 1
            elif target and target.endswith(".close"):
                if self._open_resources > 0:
                    self._open_resources -= 1
        elif instruction.opname in ("RETURN_VALUE", "RETURN_CONST"):
            if self._open_resources > 0:
                count = self._open_resources
                self._open_resources = 0
                return Issue(
                    kind=IssueKind.RESOURCE_LEAK,
                    message=f"Potential resource leak: {count} unclosed resources",
                    pc=state.pc,
                )
        return None
