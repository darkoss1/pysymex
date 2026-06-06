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

"""Unreachable Code specialized detector module.

Checks if paths are mathematically unreachable (i.e. path constraints are unsatisfiable).

Bug Class Detected:
    Unreachable / Dead Code.

Required Evidence:
    Unsatisfiable path constraints during conditional jump check.

Issue Kinds:
    IssueKind.UNREACHABLE_CODE
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex.analysis.detectors.detector.contract import Detector
from pysymex.analysis.detectors.detector.types import DisInstruction, IsSatFn, Issue, IssueKind
from pysymex.core.solver.unsat import extract_unsat_core
from pysymex.logger import get_logger

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState

logger = get_logger(__name__)
_SOLVER_FAILURES = (z3.Z3Exception, OSError, RuntimeError, ValueError)


class UnreachableCodeDetector(Detector):
    """Detects unreachable code paths."""

    name = "unreachable-code"
    description = "Detects unreachable code"
    issue_kind = IssueKind.UNREACHABLE_CODE
    relevant_opcodes = frozenset(
        {
            "POP_JUMP_IF_FALSE",
            "POP_JUMP_IF_TRUE",
            "JUMP_FORWARD",
            "JUMP_BACKWARD",
            "JUMP_BACKWARD_NO_INTERRUPT",
            "JUMP_IF_TRUE_OR_POP",
            "JUMP_IF_FALSE_OR_POP",
        }
    )

    def check(
        self,
        state: VMState,
        instruction: DisInstruction,
        is_satisfiable_fn: IsSatFn,
    ) -> Issue | None:
        """Check if current code is unreachable."""
        if instruction.opname not in self.relevant_opcodes:
            return None
        constraints = list(state.path_constraints)
        if _path_is_satisfiable(constraints, is_satisfiable_fn):
            return None
        core_result = extract_unsat_core(constraints)
        if core_result is None or not core_result.core:
            return None
        return Issue(
            kind=IssueKind.UNREACHABLE_CODE,
            message="Code path is mathematically unreachable",
            constraints=core_result.core,
            pc=state.pc,
        )


def _path_is_satisfiable(constraints: list[z3.BoolRef], is_satisfiable_fn: IsSatFn) -> bool:
    """Return SAT evidence, treating callback failures as inconclusive."""
    try:
        return is_satisfiable_fn(constraints)
    except _SOLVER_FAILURES:
        logger.debug("Unreachable-code path feasibility check failed; treating as inconclusive")
        return True
