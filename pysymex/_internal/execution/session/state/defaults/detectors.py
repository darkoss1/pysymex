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

"""Detector cache and publication defaults for execution sessions."""

from __future__ import annotations

from collections import OrderedDict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex._internal.analysis.detectors.detector.types import IssueKind
    from pysymex._internal.execution.detectors.records import (
        DeferredDetectorIssue,
        DetectorQueryCacheEntry,
    )


def default_detector_query_cache() -> OrderedDict[int, list[DetectorQueryCacheEntry]]:
    return OrderedDict()


def default_deferred_detector_issues() -> list[DeferredDetectorIssue]:
    return []


def default_reported_detector_sites() -> set[tuple[int, int, IssueKind]]:
    return set()


def default_suppressed_detector_offsets() -> set[int]:
    return set()
