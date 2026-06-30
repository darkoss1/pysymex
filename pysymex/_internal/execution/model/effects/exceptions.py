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

"""Model exception side-effect issue evidence."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.detector.issue_evidence import (
    constraints_extend_inconclusive_path,
    issue_from_inconclusive_evidence,
)
from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.exceptions.policy import issue_kind_for_exception
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.solver.constraints.literals import exact_bool_literal
from pysymex._internal.models.contracts.results import SideEffects

if TYPE_CHECKING:
    from collections.abc import Callable

    import z3


def issue_from_raised_effect(
    effect: object,
    *,
    pc: int,
    constraints_prefix: list[z3.BoolRef],
    path_may_be_feasible: Callable[[list[z3.BoolRef]], bool] | None,
    last_inconclusive_feasibility_len: int,
) -> Issue | None:
    """Create an issue from an explicit model raised-exception effect."""
    if not SideEffects.is_raised_exception(effect):
        return None
    issue_kind_name = effect["issue_kind"]
    issue_kind = IssueKind.__members__.get(issue_kind_name, IssueKind.RUNTIME_ERROR)
    message = f"{effect['source']} raised {effect['exception_type']}: {effect['message']}"
    return _issue_from_model_exception_evidence(
        issue_kind=issue_kind,
        message=message,
        constraints_prefix=constraints_prefix,
        constraints=constraints_prefix,
        pc=pc,
        path_may_be_feasible=path_may_be_feasible,
        last_inconclusive_feasibility_len=last_inconclusive_feasibility_len,
    )


def issues_from_potential_exception_effects(
    side_effects: dict[str, object],
    *,
    pc: int,
    constraints_prefix: list[z3.BoolRef],
    path_may_be_feasible: Callable[[list[z3.BoolRef]], bool] | None,
    last_inconclusive_feasibility_len: int,
) -> list[Issue]:
    """Create issues from all feasible potential-exception model side effects."""
    issues: list[Issue] = []
    issue = _issue_from_potential_exception_effect(
        side_effects.get("potential_exception"),
        pc=pc,
        constraints_prefix=constraints_prefix,
        path_may_be_feasible=path_may_be_feasible,
        last_inconclusive_feasibility_len=last_inconclusive_feasibility_len,
    )
    if issue is not None:
        issues.append(issue)

    potential_exceptions_obj = side_effects.get("potential_exceptions")
    if SideEffects.is_potential_exception_sequence(potential_exceptions_obj):
        for potential_exception in potential_exceptions_obj:
            issue = _issue_from_potential_exception_effect(
                potential_exception,
                pc=pc,
                constraints_prefix=constraints_prefix,
                path_may_be_feasible=path_may_be_feasible,
                last_inconclusive_feasibility_len=last_inconclusive_feasibility_len,
            )
            if issue is not None:
                issues.append(issue)
    return issues


def _issue_from_potential_exception_effect(
    effect: object,
    *,
    pc: int,
    constraints_prefix: list[z3.BoolRef],
    path_may_be_feasible: Callable[[list[z3.BoolRef]], bool] | None,
    last_inconclusive_feasibility_len: int,
) -> Issue | None:
    """Create an issue from one feasible potential-exception effect."""
    if not SideEffects.is_potential_exception(effect):
        return None
    exc_type = effect["type"]
    issue_kind = issue_kind_for_exception(exc_type)
    if issue_kind is IssueKind.UNHANDLED_EXCEPTION:
        return None
    constraints = [*constraints_prefix, effect["condition"]]
    return _issue_from_model_exception_evidence(
        issue_kind=issue_kind,
        message=f"Possible {exc_type}: {effect['message']}",
        constraints_prefix=constraints_prefix,
        constraints=constraints,
        pc=pc,
        path_may_be_feasible=path_may_be_feasible,
        last_inconclusive_feasibility_len=last_inconclusive_feasibility_len,
    )


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
