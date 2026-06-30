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

"""Empty-iterable ValueError evidence for CALL-family detection."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.detector.types import IsSatFn, Issue
from pysymex._internal.analysis.detectors.runtime.value.issues import satisfiable_path_evidence
from pysymex._internal.analysis.detectors.runtime.value.literals import is_known_empty_iterable
from pysymex._internal.core.outcome import IssueKind

if TYPE_CHECKING:
    from collections.abc import Sequence

    from pysymex._internal.core.state.record import VMState


def empty_iterable_value_error_issue(
    state: VMState,
    solver_check: IsSatFn,
    lowered_target: str,
    argc: int,
    args: Sequence[object],
) -> Issue | None:
    """Return an issue for ``min`` or ``max`` on a known-empty iterable."""
    if lowered_target not in {"min", "builtins.min", "max", "builtins.max"} or argc != 1:
        return None
    sat_evidence = satisfiable_path_evidence(state, solver_check)
    if sat_evidence is None:
        return None
    constraints, model = sat_evidence
    if not is_known_empty_iterable(args[0], constraints):
        return None
    return Issue(
        kind=IssueKind.VALUE_ERROR,
        message=f"Potential ValueError: {lowered_target}() arg is an empty sequence",
        constraints=constraints,
        model=model,
        pc=state.pc,
    )
