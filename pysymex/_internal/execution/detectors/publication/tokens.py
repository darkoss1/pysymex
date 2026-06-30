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

"""Validation for core-neutral deferred detector publication tokens."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.outcome import IssueKind

if TYPE_CHECKING:
    from pysymex._internal.core.state.deferred import DeferredStateIssue
    from pysymex._internal.execution.detectors.publication.types import DetectorSiteKey


def detector_issue_payload(deferred: DeferredStateIssue) -> Issue:
    """Return a detector issue payload from a core-neutral deferred token."""
    issue = deferred.issue
    if not isinstance(issue, Issue):
        msg = "deferred detector token payload must be an Issue"
        raise TypeError(msg)
    return issue


def detector_site_key(deferred: DeferredStateIssue) -> DetectorSiteKey:
    """Return the detector publication key from a core-neutral deferred token."""
    site_key: object = deferred.site_key
    if not isinstance(site_key, tuple):
        msg = "deferred detector token site_key must be (int, int, IssueKind)"
        raise TypeError(msg)
    parts = cast("tuple[object, ...]", site_key)
    if len(parts) != 3:
        msg = "deferred detector token site_key must be (int, int, IssueKind)"
        raise TypeError(msg)
    instruction_list_id, pc, kind = parts
    if not isinstance(instruction_list_id, int) or not isinstance(pc, int):
        msg = "deferred detector token site_key must be (int, int, IssueKind)"
        raise TypeError(msg)
    if not isinstance(kind, IssueKind):
        msg = "deferred detector token site_key must be (int, int, IssueKind)"
        raise TypeError(msg)
    return (instruction_list_id, pc, kind)
