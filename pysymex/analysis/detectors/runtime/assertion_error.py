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

from pysymex.core.solver.engine import get_model, is_satisfiable
from pysymex.analysis.detectors.base import Detector, Issue, IssueKind, IsSatFn


class AssertionErrorDetector(Detector):
    """Detects failing assertions."""

    name = "assertion-error"
    description = "Detects failing assertions"
    issue_kind = IssueKind.ASSERTION_ERROR
    relevant_opcodes = frozenset({"RAISE_VARARGS"})

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Check for assertion failures."""
        if instruction.opname != "RAISE_VARARGS":
            return None

        is_assertion = False
        if state.stack:
            top = state.peek()
            name = getattr(top, "name", "") or getattr(top, "_name", "") or ""
            if "AssertionError" in str(name):
                is_assertion = True
        if not is_assertion:
            return None

        constraints = list(state.path_constraints)
        if not is_satisfiable(constraints):
            return None
        return Issue(
            kind=IssueKind.ASSERTION_ERROR,
            message="Possible assertion failure",
            constraints=constraints,
            model=get_model(constraints),
            pc=state.pc,
        )
