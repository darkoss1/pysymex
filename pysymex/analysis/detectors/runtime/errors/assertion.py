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

"""Detect assertion failures (‘assert’ statements that can raise ``AssertionError``).

Bug class:
    ``AssertionError`` raised by ``assert expr`` on a satisfiable path.

Evidence:
    A ``RAISE_VARARGS`` instruction raising ``AssertionError``, with
    satisfiable path constraints.

Issue kind:
    ``IssueKind.ASSERTION_ERROR``.

Known false-positive conditions:
    Requires either a stack value matching ``AssertionError`` or a preceding
    ``LOAD_ASSERTION_ERROR`` within a small look-back window.  Paths that
    raise ``AssertionError`` via custom wrappers may be missed (false negative).
"""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState

from pysymex.analysis.detectors.detector.contract import Detector
from pysymex.analysis.detectors.detector.issue_evidence import (
    constraints_extend_inconclusive_path,
    issue_from_feasibility_evidence,
)
from pysymex.analysis.detectors.detector.types import IsSatFn, Issue, IssueKind
from pysymex.analysis.detectors.feasibility import get_model_if_satisfiable_result


class AssertionErrorDetector(Detector):
    """Detect failing ``assert`` statements via satisfiability analysis.

    Bug class:
        ``AssertionError`` — an ``assert`` statement whose condition is
        satisfiably false under the current path constraints.

    Evidence:
        A ``RAISE_VARARGS`` instruction with ``AssertionError`` on the stack or
        a preceding ``LOAD_ASSERTION_ERROR`` in the look-back window, and
        satisfiable path constraints.

    Issue kind:
        ``IssueKind.ASSERTION_ERROR``.

    Known false-positive conditions:
        If a non-assertion ``raise AssertionError(...)`` is used, this detector
        may produce an issue (conservative over-approximation).
    """

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
        """Inspect *instruction* for an ``AssertionError`` raise on a feasible path.

        Heuristically identifies assertion raises via stack inspection and
        a look-back window over preceding opcodes.
        """
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
        model_result = get_model_if_satisfiable_result(constraints, _solver_check)
        return issue_from_feasibility_evidence(
            result=model_result,
            kind=IssueKind.ASSERTION_ERROR,
            message="Possible assertion failure (AssertionError raised)",
            constraints=constraints,
            pc=state.pc,
            path_is_inconclusive=constraints_extend_inconclusive_path(
                path_constraints=list(state.path_constraints),
                constraints=constraints,
                last_inconclusive_feasibility_len=state.last_inconclusive_feasibility_len,
            ),
        )
