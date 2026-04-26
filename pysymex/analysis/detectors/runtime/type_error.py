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
import z3
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.core.state import VMState

from pysymex.core.types.havoc import is_havoc
from pysymex.core.solver.engine import get_model, is_satisfiable
from pysymex.core.types.scalars import (
    SymbolicString,
    SymbolicValue,
)
from pysymex.analysis.detectors.base import Detector, Issue, IssueKind, IsSatFn


class TypeErrorDetector(Detector):
    """Detects type errors in binary operations (e.g. string + int)."""

    name = "type-error"
    description = "Detects type mismatches"
    issue_kind = IssueKind.TYPE_ERROR
    relevant_opcodes = frozenset({"BINARY_OP"})

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Check."""
        if instruction.opname == "BINARY_OP":
            if len(state.stack) < 2:
                return None
            op = instruction.argrepr
            left = state.stack[-2]
            right = state.stack[-1]
            if op == "+":
                if isinstance(left, SymbolicString) and isinstance(right, SymbolicValue):
                    type_error: list[z3.BoolRef] = [
                        *state.path_constraints,
                        right.is_int,
                    ]
                    if is_satisfiable(type_error):
                        confidence = 1.0
                        if is_havoc(right):
                            confidence = 0.5
                        elif hasattr(right, "affinity_type") and right.affinity_type == "int":
                            confidence = 0.9

                        return Issue(
                            kind=IssueKind.TYPE_ERROR,
                            message=f"Cannot {op} string and int",
                            constraints=type_error,
                            model=get_model(type_error),
                            pc=state.pc,
                            confidence=confidence,
                        )
        return None
