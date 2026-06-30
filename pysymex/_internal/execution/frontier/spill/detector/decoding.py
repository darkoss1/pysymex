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

"""Detector-sidecar spill decoding."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.execution.detectors.records import DeferredDetectorIssue
from pysymex._internal.execution.frontier.spill.detector.issues import decode_issue
from pysymex._internal.execution.frontier.spill.detector.site.keys import decode_site_key
from pysymex._internal.execution.frontier.spill.detector.types import SpillDetectorDecodeError
from pysymex._internal.execution.frontier.spill.fields.decode import object_payload

if TYPE_CHECKING:
    from pysymex._internal.core.state.deferred import DeferredStateIssue


def decode_detector_issues(raw_issues: object) -> list[DeferredStateIssue]:
    """Decode detector sidecars from a spill payload."""
    if raw_issues is None:
        return []
    if not isinstance(raw_issues, list):
        msg = "deferred detector issues must be a list"
        raise SpillDetectorDecodeError(msg)
    return [_decode_deferred_detector(raw_issue) for raw_issue in cast("list[object]", raw_issues)]


def _decode_deferred_detector(raw_issue: object) -> DeferredDetectorIssue:
    payload = object_payload(raw_issue)
    if payload is None or payload.get("kind") != "deferred_detector_issue":
        msg = "deferred detector issue is malformed"
        raise SpillDetectorDecodeError(msg)
    issue = decode_issue(payload.get("issue"))
    site_key = decode_site_key(payload.get("site_key"))
    return DeferredDetectorIssue(issue, site_key)
