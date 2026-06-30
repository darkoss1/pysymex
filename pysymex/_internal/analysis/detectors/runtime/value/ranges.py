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

"""Range zero-step ValueError evidence for CALL-family detection."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.analysis.detectors.detector.types import IsSatFn, Issue
from pysymex._internal.analysis.detectors.feasibility import get_model_if_satisfiable_result
from pysymex._internal.analysis.detectors.runtime.overflow import as_symbolic_int
from pysymex._internal.core.outcome import IssueKind

if TYPE_CHECKING:
    from collections.abc import Sequence

    from pysymex._internal.core.state.record import VMState


def range_zero_step_issue(
    state: VMState,
    args: Sequence[object],
    is_satisfiable_fn: IsSatFn,
) -> Issue | None:
    """Check ``range(start, stop, step)`` for a satisfiable zero step."""
    if len(args) != 3:
        return None
    step = as_symbolic_int(args[2])
    if step is None:
        return None
    constraints = [
        *state.path_constraints,
        z3.Or(step.is_int, step.is_bool),
        step.z3_int == 0,
    ]
    model = get_model_if_satisfiable_result(constraints, is_satisfiable_fn).model
    if model is None:
        return None
    return Issue(
        kind=IssueKind.VALUE_ERROR,
        message="Potential ValueError: range() arg 3 must not be zero",
        constraints=constraints,
        model=model,
        pc=state.pc,
    )
