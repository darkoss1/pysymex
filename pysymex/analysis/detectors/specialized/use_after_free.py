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


class UseAfterFreeDetector(Detector):
    """Detects use-after-free patterns (e.g. using a closed file handle).

    Attributes:
        _freed_resources: Object IDs marked as freed/closed.
    """

    name = "use-after-free"
    description = "Detects use of released resources"
    issue_kind = IssueKind.ATTRIBUTE_ERROR
    relevant_opcodes = frozenset({"CALL", "CALL_FUNCTION", "LOAD_METHOD", "LOAD_ATTR"})

    def __init__(self) -> None:
        self._freed_vars: set[str] = set()

    def check(
        self,
        state: VMState,
        instruction: DisInstruction,
        is_satisfiable_fn: IsSatFn,
    ) -> Issue | None:
        """Check for use of freed/closed resources."""
        if instruction.opname in ("CALL", "CALL_FUNCTION"):
            argc: int = (
                instruction.argval if instruction.argval is not None else (instruction.arg or 0)
            )
            target = resolve_target_name(state, argc)
            if target and target.endswith(".close"):
                if len(state.stack) >= argc + 2:
                    receiver = state.stack[-(argc + 2)]
                    receiver_name = get_named_value_name(receiver)
                    if receiver_name is not None:
                        self._freed_vars.add(receiver_name)
        elif instruction.opname in ("LOAD_METHOD", "LOAD_ATTR"):
            if state.stack:
                top = state.peek()
                top_name = get_named_value_name(top)
                if top_name is not None and top_name in self._freed_vars:
                    return Issue(
                        kind=IssueKind.ATTRIBUTE_ERROR,
                        message=f"Use of closed/freed resource: {top_name}",
                        pc=state.pc,
                    )
        return None
