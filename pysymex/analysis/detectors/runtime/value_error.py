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


class ValueErrorDetector(Detector):
    """Detects potential ValueError exceptions.

    Checks for:
    - str.index() when substring may not be found
    - list.remove() when element may not exist
    - int() with non-numeric strings
    """

    name = "value-error"
    description = "Detects potential ValueError exceptions"
    issue_kind = IssueKind.VALUE_ERROR
    relevant_opcodes = frozenset({"CALL", "CALL_FUNCTION", "CALL_METHOD"})

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Check."""
        if instruction.opname not in ("CALL", "CALL_FUNCTION", "CALL_METHOD"):
            return None
        if len(state.stack) < 2:
            return None
        for var_name, var_val in state.local_vars.items():
            if hasattr(var_val, "_potential_exception"):
                exc = getattr(var_val, "_potential_exception", None)
                if exc == "ValueError":
                    return Issue(
                        kind=IssueKind.VALUE_ERROR,
                        message=f"Potential ValueError from {var_name}",
                        constraints=list(state.path_constraints),
                        model=get_model(list(state.path_constraints)),
                        pc=state.pc,
                    )
        return None
