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

"""Result states for index-error bounds detector queries."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex._internal.analysis.detectors.detector.types import Issue


class IndexBoundsCheckStatus(Enum):
    """Outcome of a pure index-bounds detector query."""

    OUT_OF_BOUNDS = "out_of_bounds"
    IN_BOUNDS = "in_bounds"
    NO_OUT_OF_BOUNDS_EVIDENCE = "no_out_of_bounds_evidence"
    INCONCLUSIVE = "inconclusive"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class IndexBoundsCheckResult:
    """Structured index-bounds evidence without collapsing uncertainty."""

    status: IndexBoundsCheckStatus
    issue: Issue | None = None
    reason: str | None = None

    @property
    def has_issue(self) -> bool:
        """Return true only when model-backed out-of-bounds evidence exists."""
        return self.status is IndexBoundsCheckStatus.OUT_OF_BOUNDS and self.issue is not None

    @staticmethod
    def out_of_bounds(issue: Issue) -> IndexBoundsCheckResult:
        """Create a model-backed out-of-bounds result."""
        return IndexBoundsCheckResult(IndexBoundsCheckStatus.OUT_OF_BOUNDS, issue=issue)

    @staticmethod
    def in_bounds(reason: str) -> IndexBoundsCheckResult:
        """Create a result for locally proved in-bounds access."""
        return IndexBoundsCheckResult(IndexBoundsCheckStatus.IN_BOUNDS, reason=reason)

    @staticmethod
    def no_evidence(reason: str) -> IndexBoundsCheckResult:
        """Create a result when no satisfiable OOB evidence was found."""
        return IndexBoundsCheckResult(
            IndexBoundsCheckStatus.NO_OUT_OF_BOUNDS_EVIDENCE,
            reason=reason,
        )

    @staticmethod
    def inconclusive(reason: str, issue: Issue | None = None) -> IndexBoundsCheckResult:
        """Create an inconclusive bounds-check result."""
        return IndexBoundsCheckResult(
            IndexBoundsCheckStatus.INCONCLUSIVE,
            issue=issue,
            reason=reason,
        )

    @staticmethod
    def unsupported(reason: str) -> IndexBoundsCheckResult:
        """Create a result for unsupported bounds-check shapes."""
        return IndexBoundsCheckResult(IndexBoundsCheckStatus.UNSUPPORTED, reason=reason)
