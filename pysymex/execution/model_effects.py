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

"""Helpers for converting model side effects into execution issues."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypedDict, TypeGuard, cast

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.models.builtins.base import is_raised_exception_effect, is_sink_event_effect


class PotentialExceptionEffect(TypedDict):
    """Structured metadata for potential modeled exceptions."""

    type: str
    message: str
    condition: z3.BoolRef


def is_potential_exception_effect(value: object) -> TypeGuard[PotentialExceptionEffect]:
    """Return whether *value* has the potential-exception side-effect shape."""
    if not isinstance(value, dict):
        return False
    dict_val = cast("dict[str, object]", value)
    exc_type = dict_val.get("type")
    message = dict_val.get("message")
    condition = dict_val.get("condition")
    return (
        isinstance(exc_type, str) and isinstance(message, str) and isinstance(condition, z3.BoolRef)
    )


_EXCEPTION_KIND_BY_TYPE = {
    "AttributeError": IssueKind.ATTRIBUTE_ERROR,
    "IndexError": IssueKind.INDEX_ERROR,
    "KeyError": IssueKind.KEY_ERROR,
    "TypeError": IssueKind.TYPE_ERROR,
    "ValueError": IssueKind.VALUE_ERROR,
}


def issues_from_model_side_effects(
    side_effects: dict[str, object],
    pc: int,
    path_constraints: list[z3.BoolRef] | None = None,
    is_sat: Callable[[list[z3.BoolRef]], bool] | None = None,
) -> list[Issue]:
    """Build detector issues from structured model side effects."""
    issues: list[Issue] = []
    constraints_prefix = list(path_constraints or [])

    raised_exception_obj = side_effects.get("raised_exception")
    if is_raised_exception_effect(raised_exception_obj):
        issue_kind_name = raised_exception_obj["issue_kind"]
        issue_kind = IssueKind.__members__.get(issue_kind_name, IssueKind.RUNTIME_ERROR)
        message = (
            f"[{raised_exception_obj['source']}] "
            f"{raised_exception_obj['exception_type']}: {raised_exception_obj['message']}"
        )
        issues.append(Issue(kind=issue_kind, message=message, pc=pc))

    potential_exception_obj = side_effects.get("potential_exception")
    if is_potential_exception_effect(potential_exception_obj):
        exc_type = potential_exception_obj["type"]
        message_text = potential_exception_obj["message"]
        condition = potential_exception_obj["condition"]
        issue_kind = _EXCEPTION_KIND_BY_TYPE.get(exc_type)
        if issue_kind is not None:
            constraints = [*constraints_prefix, condition]
            if is_sat is None or is_sat(constraints):
                issues.append(
                    Issue(
                        kind=issue_kind,
                        message=f"Possible {exc_type}: {message_text}",
                        constraints=constraints,
                        pc=pc,
                    )
                )

    sink_event_obj = side_effects.get("sink_event")
    if is_sink_event_effect(sink_event_obj) and sink_event_obj["severity"] == "critical":
        sink_type = sink_event_obj["sink_type"]
        message = f"[{sink_event_obj['source']}] Dynamic code sink reached: {sink_type}"
        issues.append(Issue(kind=IssueKind.RUNTIME_ERROR, message=message, pc=pc))

    return issues
