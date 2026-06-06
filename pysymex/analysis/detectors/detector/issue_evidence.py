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

"""Issue construction helpers for model-backed and inconclusive detector evidence."""

from __future__ import annotations

from typing import Final

import z3

from pysymex.analysis.detectors.detector.types import Issue, IssueKind
from pysymex.analysis.detectors.feasibility import FeasibilityModelResult
from pysymex.core.solver.constraints.literals import exact_bool_literal

INCONCLUSIVE_DETECTOR_CONFIDENCE: Final = 0.5
_INCONCLUSIVE_PREFIX: Final = "Path feasibility inconclusive; "
_SIMPLIFY_FAILURES = (z3.Z3Exception, OSError, RuntimeError, ValueError)


def issue_from_feasibility_evidence(
    *,
    result: FeasibilityModelResult,
    kind: IssueKind,
    message: str,
    constraints: list[z3.BoolRef],
    pc: int,
    confidence: float = 1.0,
    likelihood: float = 1.0,
    path_is_inconclusive: bool = False,
) -> Issue | None:
    """Build an issue from detector feasibility evidence without overstating certainty."""
    if result.is_sat and result.model is not None:
        return Issue(
            kind=kind,
            message=message,
            constraints=constraints,
            model=result.model,
            pc=pc,
            confidence=confidence,
            likelihood=likelihood,
        )
    if not result.is_inconclusive and not path_is_inconclusive:
        return None
    if _constraints_locally_disproved(constraints):
        return None
    return issue_from_inconclusive_evidence(
        kind=kind,
        message=message,
        constraints=constraints,
        pc=pc,
        confidence=confidence,
        likelihood=likelihood,
    )


def issue_from_inconclusive_evidence(
    *,
    kind: IssueKind,
    message: str,
    constraints: list[z3.BoolRef],
    pc: int,
    confidence: float = 1.0,
    likelihood: float = 1.0,
    detector_name: str | None = None,
) -> Issue:
    """Build a low-confidence issue for a path already classified inconclusive."""
    return Issue(
        kind=kind,
        message=_inconclusive_message(message),
        constraints=constraints,
        model=None,
        pc=pc,
        confidence=min(confidence, INCONCLUSIVE_DETECTOR_CONFIDENCE),
        likelihood=min(likelihood, INCONCLUSIVE_DETECTOR_CONFIDENCE),
        detector_name=detector_name,
    )


def constraints_extend_inconclusive_path(
    *,
    path_constraints: list[z3.BoolRef],
    constraints: list[z3.BoolRef],
    last_inconclusive_feasibility_len: int,
) -> bool:
    """Return whether a detector query extends a path prefix already marked inconclusive."""
    if last_inconclusive_feasibility_len < 0:
        return False
    if last_inconclusive_feasibility_len > len(path_constraints):
        return False
    prefix = path_constraints[:last_inconclusive_feasibility_len]
    if len(constraints) < len(prefix):
        return False
    return all(
        expected is actual or z3.eq(expected, actual)
        for expected, actual in zip(prefix, constraints[: len(prefix)], strict=True)
    )


def _inconclusive_message(message: str) -> str:
    """Return a stable inconclusive issue message without double-prefixing."""
    if message.startswith(_INCONCLUSIVE_PREFIX):
        return message
    return f"{_INCONCLUSIVE_PREFIX}{message}"


def _constraints_locally_disproved(constraints: list[z3.BoolRef]) -> bool:
    """Return whether detector issue constraints are syntactically contradictory."""
    if any(exact_bool_literal(constraint) is False for constraint in constraints):
        return True
    try:
        return z3.is_false(z3.simplify(z3.And(*constraints)))
    except _SIMPLIFY_FAILURES:
        return False


__all__ = [
    "INCONCLUSIVE_DETECTOR_CONFIDENCE",
    "constraints_extend_inconclusive_path",
    "issue_from_feasibility_evidence",
    "issue_from_inconclusive_evidence",
]
