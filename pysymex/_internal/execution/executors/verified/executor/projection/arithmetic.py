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

"""Arithmetic detector issue projection for verified execution."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.contracts.reports.adapters import extract_counterexample_from_model
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.execution.executors.verified.types import ArithmeticIssue

if TYPE_CHECKING:
    from pysymex._internal.analysis.detectors.detector.types import Issue

_PROJECTABLE_ARITHMETIC_ISSUE_KINDS = frozenset((IssueKind.DIVISION_BY_ZERO, IssueKind.OVERFLOW))


def is_projectable_arithmetic_issue(issue: Issue) -> bool:
    """Return whether a core detector issue belongs in verified arithmetic output."""
    return issue.kind in _PROJECTABLE_ARITHMETIC_ISSUE_KINDS


def project_arithmetic_issue(issue: Issue) -> ArithmeticIssue:
    """Project a core detector arithmetic issue into verified execution output."""
    return ArithmeticIssue(
        kind=issue.kind.name.lower(),
        expression=issue.message,
        message=issue.message,
        line_number=issue.line_number,
        counterexample=extract_counterexample_from_model(issue.model),
    )
