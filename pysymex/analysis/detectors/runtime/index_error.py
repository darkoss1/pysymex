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
from pysymex.core.types.checks import is_type_subscription
from pysymex.core.types.scalars import (
    SymbolicList,
    SymbolicValue,
)
from pysymex.analysis.detectors.base import (
    Detector,
    Issue,
    IssueKind,
    IsSatFn,
    GetModelFn,
    is_list_of_objects,
    is_tuple_of_objects,
)


def pure_check_index_bounds(
    container: object,
    index: object,
    path_constraints: list[z3.BoolRef],
    pc: int,
    is_satisfiable_fn: IsSatFn = is_satisfiable,
    get_model_fn: GetModelFn = get_model,
) -> Issue | None:
    """Pure: check if *index* can be out-of-bounds for *container*."""
    if is_type_subscription(container):
        return None
    if not isinstance(index, SymbolicValue):
        return None

    lower_bound: z3.ArithRef
    upper_bound: z3.ArithRef
    container_name: str
    confidence = 1.0

    if isinstance(container, SymbolicList):
        lower_bound = -container.z3_len
        upper_bound = container.z3_len
        container_name = container.name
        if is_havoc(index) or is_havoc(container):
            confidence = 0.5
        elif hasattr(index, "affinity_type") and index.affinity_type == "int":
            confidence = 0.9
    elif is_list_of_objects(container):
        concrete_len = len(container)
        lower_bound = z3.IntVal(-concrete_len)
        upper_bound = z3.IntVal(concrete_len)
        container_name = "list"
        if is_havoc(index):
            confidence = 0.5
        elif hasattr(index, "affinity_type") and index.affinity_type == "int":
            confidence = 0.9
    elif is_tuple_of_objects(container):
        concrete_len = len(container)
        lower_bound = z3.IntVal(-concrete_len)
        upper_bound = z3.IntVal(concrete_len)
        container_name = "list"
        if is_havoc(index):
            confidence = 0.5
        elif hasattr(index, "affinity_type") and index.affinity_type == "int":
            confidence = 0.9
    else:
        return None

    oob_constraint = [
        *path_constraints,
        index.is_int,
        z3.Or(
            index.z3_int < lower_bound,
            index.z3_int >= upper_bound,
        ),
    ]
    if is_satisfiable_fn(oob_constraint):
        return Issue(
            kind=IssueKind.INDEX_ERROR,
            message=f"Possible index out of bounds: {container_name}[{index.name}]",
            constraints=oob_constraint,
            model=get_model_fn(oob_constraint),
            pc=pc,
            confidence=confidence,
        )
    return None


class IndexErrorDetector(Detector):
    """Detects out-of-bounds array/list access."""

    name = "index-error"
    description = "Detects out-of-bounds indexing"
    issue_kind = IssueKind.INDEX_ERROR
    relevant_opcodes = frozenset({"BINARY_SUBSCR"})

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Check for index out of bounds errors in lists."""
        if instruction.opname != "BINARY_SUBSCR":
            return None
        if len(state.stack) < 2:
            return None
        return pure_check_index_bounds(
            state.stack[-2],
            state.stack[-1],
            list(state.path_constraints),
            state.pc,
        )
