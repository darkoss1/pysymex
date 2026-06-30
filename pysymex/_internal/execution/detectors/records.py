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

"""Detector cache and deferred-publication records."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex._internal.core.state.deferred import DeferredStateIssue

if TYPE_CHECKING:
    import z3

    from pysymex._internal.analysis.detectors.detector.types import Issue
    from pysymex._internal.core.outcome import IssueKind


@dataclass(frozen=True, slots=True)
class DetectorQueryCacheEntry:
    """Cached definitive SAT/UNSAT outcome for one detector feasibility query."""

    constraints: tuple[z3.BoolRef, ...]
    result: bool


@dataclass(frozen=True, slots=True)
class DeferredDetectorIssue(DeferredStateIssue):
    """Detector issue awaiting runtime exception-handler or ``__exit__`` resolution.

    Attributes:
        issue: Issue payload to publish if not suppressed.
        site_key: ``(instruction_list_id, pc, issue_kind)`` de-duplication key.

    """

    issue: Issue
    site_key: tuple[int, int, IssueKind]
