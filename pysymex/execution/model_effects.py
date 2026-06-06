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

"""Convert structured model side effects into emitted execution issues."""

from __future__ import annotations

from collections.abc import Callable

import z3

from pysymex.analysis.detectors.detector.issue_evidence import (
    constraints_extend_inconclusive_path,
    issue_from_inconclusive_evidence,
)
from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.solver.constraints.literals import exact_bool_literal
from pysymex.models.builtins.results import (
    is_potential_exception_effect,
    is_potential_exception_effect_sequence,
    is_raised_exception_effect,
    is_sink_event_effect,
)


_EXCEPTION_KIND_BY_TYPE = {
    "AttributeError": IssueKind.ATTRIBUTE_ERROR,
    "IndexError": IssueKind.INDEX_ERROR,
    "KeyError": IssueKind.KEY_ERROR,
    "OverflowError": IssueKind.OVERFLOW,
    "TypeError": IssueKind.TYPE_ERROR,
    "ValueError": IssueKind.VALUE_ERROR,
    "ZeroDivisionError": IssueKind.DIVISION_BY_ZERO,
}


def issues_from_model_side_effects(
    side_effects: dict[str, object],
    pc: int,
    path_constraints: list[z3.BoolRef] | None = None,
    path_may_be_feasible: Callable[[list[z3.BoolRef]], bool] | None = None,
    last_inconclusive_feasibility_len: int = -1,
) -> list[Issue]:
    """Return issues represented by known structured model-effect payloads.

    Inspects side effects dictionary for raised exceptions, potential exceptions, and
    sink events, converting them into Issue objects.

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

    raised_exception_obj = side_effects.get("raised_exception")
    if is_raised_exception_effect(raised_exception_obj):
        issue_kind_name = raised_exception_obj["issue_kind"]
        issue_kind = IssueKind.__members__.get(issue_kind_name, IssueKind.RUNTIME_ERROR)
        message = (
            f"{raised_exception_obj['source']} raised "
            f"{raised_exception_obj['exception_type']}: {raised_exception_obj['message']}"
        )
        issue = _issue_from_model_exception_evidence(
            issue_kind=issue_kind,
            message=message,
            constraints_prefix=constraints_prefix,
            constraints=constraints_prefix,
            pc=pc,
            path_may_be_feasible=path_may_be_feasible,
            last_inconclusive_feasibility_len=last_inconclusive_feasibility_len,
        )
        if issue is not None:
            issues.append(issue)

    def append_potential_exception(effect: object) -> None:
        if not is_potential_exception_effect(effect):
            return
        exc_type = effect["type"]
        message_text = effect["message"]
        condition = effect["condition"]
        issue_kind = _EXCEPTION_KIND_BY_TYPE.get(exc_type)
        if issue_kind is not None:
            constraints = [*constraints_prefix, condition]
            issue = _issue_from_model_exception_evidence(
                issue_kind=issue_kind,
                message=f"Possible {exc_type}: {message_text}",
                constraints_prefix=constraints_prefix,
                constraints=constraints,
                pc=pc,
                path_may_be_feasible=path_may_be_feasible,
                last_inconclusive_feasibility_len=last_inconclusive_feasibility_len,
            )
            if issue is not None:
                issues.append(issue)

    append_potential_exception(side_effects.get("potential_exception"))

    potential_exceptions_obj = side_effects.get("potential_exceptions")
    if is_potential_exception_effect_sequence(potential_exceptions_obj):
        for potential_exception in potential_exceptions_obj:
            append_potential_exception(potential_exception)

    sink_event_obj = side_effects.get("sink_event")
    if is_sink_event_effect(sink_event_obj) and sink_event_obj["severity"] == "critical":
        sink_type = sink_event_obj["sink_type"]
        message = f"[{sink_event_obj['source']}] Dynamic code sink reached: {sink_type}"
        issues.append(
            Issue(
                kind=IssueKind.RUNTIME_ERROR,
                message=message,
                pc=pc,
                detector_name="model-side-effect",
            )
        )

    return issues


def _issue_from_model_exception_evidence(
    *,
    issue_kind: IssueKind,
    message: str,
    constraints_prefix: list[z3.BoolRef],
    constraints: list[z3.BoolRef],
    pc: int,
    path_may_be_feasible: Callable[[list[z3.BoolRef]], bool] | None,
    last_inconclusive_feasibility_len: int,
) -> Issue | None:
    """Create a model-side-effect issue without promoting unknown paths to definite bugs."""
    if path_may_be_feasible is not None and _constraints_may_extend_inconclusive_model_path(
        constraints_prefix=constraints_prefix,
        constraints=constraints,
        last_inconclusive_feasibility_len=last_inconclusive_feasibility_len,
    ):
        return issue_from_inconclusive_evidence(
            kind=issue_kind,
            message=message,
            constraints=constraints,
            pc=pc,
            detector_name="model-side-effect",
        )
    if path_may_be_feasible is None or path_may_be_feasible(constraints):
        return Issue(
            kind=issue_kind,
            message=message,
            constraints=constraints,
            pc=pc,
            detector_name="model-side-effect",
        )
    return None


def _constraints_may_extend_inconclusive_model_path(
    *,
    constraints_prefix: list[z3.BoolRef],
    constraints: list[z3.BoolRef],
    last_inconclusive_feasibility_len: int,
) -> bool:
    """Return whether a model exception sits under an already-inconclusive path prefix."""
    if any(exact_bool_literal(constraint) is False for constraint in constraints):
        return False
    return constraints_extend_inconclusive_path(
        path_constraints=constraints_prefix,
        constraints=constraints,
        last_inconclusive_feasibility_len=last_inconclusive_feasibility_len,
    )
