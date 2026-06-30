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

"""Model side-effect issue conversion orchestration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.model.effects.exceptions import (
    issue_from_raised_effect,
    issues_from_potential_exception_effects,
)
from pysymex._internal.execution.model.effects.sinks import issue_from_sink_event

if TYPE_CHECKING:
    from collections.abc import Callable

    import z3

    from pysymex._internal.analysis.detectors.detector.types import Issue


def issues_from_model_side_effects(
    side_effects: dict[str, object],
    pc: int,
    path_constraints: list[z3.BoolRef] | None = None,
    path_may_be_feasible: Callable[[list[z3.BoolRef]], bool] | None = None,
    last_inconclusive_feasibility_len: int = -1,
) -> list[Issue]:
    """Return issues represented by known structured model-effect payloads.

    Inspects side effects dictionary for raised exceptions, potential exceptions,
    and sink events, converting them into Issue objects.

    Args:
        side_effects: Dictionary containing the side effects to evaluate.
        pc: Program counter offset at which these issues occurred.
        path_constraints: Optional path constraints list to evaluate potential exceptions against.
        path_may_be_feasible: Optional callback used to evaluate whether
            potential exception conditions remain feasible.
        last_inconclusive_feasibility_len: Constraint-prefix length of the most recent
            inconclusive path-feasibility check. A model exception on such a path
            may become a low-confidence possible issue, but never a definite one.

    Returns:
        List of compiled Issue objects representing detected side effect conditions.

    Notes:
        Explicit raised-exception effects are retained when the callback is
        absent or confirms the active path constraints are satisfiable.
        Conditional exception effects additionally append their guard
        condition before the same feasibility check.

    """
    issues: list[Issue] = []
    constraints_prefix = list(path_constraints or [])
    exception_issue = issue_from_raised_effect(
        side_effects.get("raised_exception"),
        pc=pc,
        constraints_prefix=constraints_prefix,
        path_may_be_feasible=path_may_be_feasible,
        last_inconclusive_feasibility_len=last_inconclusive_feasibility_len,
    )
    if exception_issue is not None:
        issues.append(exception_issue)

    issues.extend(
        issues_from_potential_exception_effects(
            side_effects,
            pc=pc,
            constraints_prefix=constraints_prefix,
            path_may_be_feasible=path_may_be_feasible,
            last_inconclusive_feasibility_len=last_inconclusive_feasibility_len,
        ),
    )

    sink_issue = issue_from_sink_event(side_effects.get("sink_event"), pc=pc)
    if sink_issue is not None:
        issues.append(sink_issue)

    return issues
