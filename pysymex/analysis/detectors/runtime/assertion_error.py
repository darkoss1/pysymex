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

import dis
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.core.state import VMState

from pysymex.core.solver.engine import get_model
from pysymex.analysis.detectors.base import Detector, Issue, IssueKind, IsSatFn


class AssertionErrorDetector(Detector):
    """Detects failing assertions."""

    name = "assertion-error"
    description = "Detects failing assertions"
    issue_kind = IssueKind.ASSERTION_ERROR
    relevant_opcodes = frozenset({"RAISE_VARARGS"})
    LOOKBACK_WINDOW = 4

    @staticmethod
    def _looks_like_assertion_marker(value: object) -> bool:
        """Return True when a stack value clearly represents AssertionError."""
        if value is AssertionError:
            return True
        if isinstance(value, AssertionError):
            return True
        name = getattr(value, "name", "") or getattr(value, "_name", "") or ""
        return "AssertionError" in str(name)

    def _has_recent_assertion_opcode(self, state: VMState) -> bool:
        """Return True when nearby bytecode constructs an AssertionError."""
        instructions = state.current_instructions
        if instructions is None:
            return False
        if state.pc <= 0:
            return False
        start = max(0, state.pc - self.LOOKBACK_WINDOW)
        for idx in range(start, state.pc):
            candidate = instructions[idx]
            opname = getattr(candidate, "opname", "")
            if opname == "LOAD_ASSERTION_ERROR":
                return True
            if opname in {"LOAD_GLOBAL", "LOAD_NAME"}:
                argval = getattr(candidate, "argval", None)
                argrepr = getattr(candidate, "argrepr", "")
                if argval == "AssertionError" or "AssertionError" in str(argrepr):
                    return True
        return False

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Check for assertion failures."""
        if instruction.opname != "RAISE_VARARGS":
            return None
        if isinstance(instruction.arg, int) and instruction.arg <= 0:
            return None

        is_assertion = False
        for offset in range(1, min(3, len(state.stack)) + 1):
            if self._looks_like_assertion_marker(state.stack[-offset]):
                is_assertion = True
                break
        if not is_assertion:
            is_assertion = self._has_recent_assertion_opcode(state)

        if not is_assertion:
            return None

        constraints = list(state.path_constraints)
        if not _solver_check(constraints):
            return None
        return Issue(
            kind=IssueKind.ASSERTION_ERROR,
            message="Possible assertion failure (AssertionError raised)",
            constraints=constraints,
            model=get_model(constraints),
            pc=state.pc,
        )
