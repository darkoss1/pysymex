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

"""Explicit potential-ValueError marker detection."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.runtime.value.issues import value_error_issue
from pysymex._internal.guards import RuntimeObjectGuards

if TYPE_CHECKING:
    from collections.abc import Iterable

    from pysymex._internal.analysis.detectors.detector.types import IsSatFn, Issue
    from pysymex._internal.core.state.record import VMState


def _iter_potential_exception_values(state: VMState) -> Iterable[tuple[str, object]]:
    """Yield possible exception-bearing values from locals and stack."""
    yield from state.local_vars.items()
    for idx, stack_value in enumerate(state.stack):
        yield f"stack_{idx}", stack_value


def _value_error_marker(value: object) -> str | None:
    """Return a marker string when *value* indicates a potential ValueError."""
    potential_exception = getattr(value, "_potential_exception", None)
    if isinstance(potential_exception, str) and potential_exception == "ValueError":
        return "ValueError"
    if RuntimeObjectGuards.tuple(potential_exception):
        for tuple_item in potential_exception:
            if isinstance(tuple_item, str) and tuple_item == "ValueError":
                return "ValueError"
    if RuntimeObjectGuards.list(potential_exception):
        for list_item in potential_exception:
            if isinstance(list_item, str) and list_item == "ValueError":
                return "ValueError"

    message = getattr(value, "error", None)
    if isinstance(message, str) and "ValueError" in message:
        return message
    return None


def potential_marker_issue(state: VMState, solver_check: IsSatFn) -> Issue | None:
    """Return an issue for values carrying an explicit potential ValueError marker."""
    for source_name, source_value in _iter_potential_exception_values(state):
        marker = _value_error_marker(source_value)
        if marker is None:
            continue
        return value_error_issue(
            state,
            solver_check,
            f"Potential ValueError from {source_name}: {marker}",
        )
    return None
