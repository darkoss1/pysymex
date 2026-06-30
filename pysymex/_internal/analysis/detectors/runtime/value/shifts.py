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

"""Negative shift-count evidence for the ValueError detector."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.analysis.detectors.detector.types import IsSatFn, Issue
from pysymex._internal.analysis.detectors.feasibility import get_model_if_satisfiable_result
from pysymex._internal.analysis.detectors.runtime.overflow import as_symbolic_int
from pysymex._internal.core.bytecode import resolve_binary_op_symbol
from pysymex._internal.core.outcome import IssueKind

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState


def check_negative_shift(
    state: VMState,
    instruction: dis.Instruction,
    is_satisfiable_fn: IsSatFn,
) -> Issue | None:
    """Check for a bitwise shift with a potentially negative shift count."""
    op_symbol = resolve_binary_op_symbol(instruction)
    op = op_symbol.removesuffix("=")
    if op not in {"<<", ">>"}:
        return None
    if len(state.stack) < 2:
        return None
    right = as_symbolic_int(state.stack[-1])
    if right is None:
        return None
    constraints = [
        *state.path_constraints,
        z3.Or(right.is_int, right.is_bool),
        right.z3_int < 0,
    ]
    model = get_model_if_satisfiable_result(constraints, is_satisfiable_fn).model
    if model is None:
        return None
    return Issue(
        kind=IssueKind.VALUE_ERROR,
        message=f"Potential ValueError: negative shift count for {op}",
        constraints=constraints,
        model=model,
        pc=state.pc,
    )
