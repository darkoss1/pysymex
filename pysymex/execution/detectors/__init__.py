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

"""Execution-side detector publication records.

This package owns typed records used while execution runs detectors, caches
detector feasibility answers, and defers detector issues across modeled
exception-handler and context-manager control flow.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.analysis.detectors.filter.core import filter_issues
from pysymex.analysis.detectors.filter.dedup import deduplicate_issues
from pysymex.core.state.deferred import DeferredStateIssue
from pysymex.execution.detectors.telemetry import (
    detector_query_constraint_excerpt,
    DetectorQueryContext,
    DetectorQueryEvent,
    DetectorQueryResultSource,
)
from pysymex.execution.fallback import FallbackEvent, FallbackKind, RiskLevel, SoundnessTag
from pysymex.execution.fallback.infrastructure import fp_filtering_event
from pysymex.logger import get_logger

if TYPE_CHECKING:
    from pysymex.execution.session.state import ExecutionSession

__all__ = [
    "DeferredDetectorIssue",
    "DetectorQueryCacheEntry",
    "DetectorQueryContext",
    "DetectorQueryEvent",
    "DetectorQueryResultSource",
    "detector_query_constraint_excerpt",
    "SOLVER_UNKNOWN_DETECTOR_QUERY_DEGRADED_PASS",
    "filter_final_issues",
    "record_detector_query_unknown",
]

SOLVER_UNKNOWN_DETECTOR_QUERY_DEGRADED_PASS: Final = "solver_unknown_detector_query"

logger = get_logger(__name__)


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


def record_detector_query_unknown(
    *,
    session: ExecutionSession,
    constraints_count: int,
    reason: str | None = None,
) -> None:
    """Record an inconclusive detector feasibility query without reporting a definite issue."""
    session.record_fallback_event(
        FallbackEvent(
            kind=FallbackKind.UNKNOWN,
            label=SOLVER_UNKNOWN_DETECTOR_QUERY_DEGRADED_PASS,
            owner="execution.detectors",
            reason=reason
            or f"solver returned unknown for detector query with {constraints_count} constraint(s)",
            soundness=SoundnessTag.INCONCLUSIVE,
            false_positive_risk=RiskLevel.MEDIUM,
            false_negative_risk=RiskLevel.MEDIUM,
        )
    )


def filter_final_issues(*, session: ExecutionSession, enable_fp_filtering: bool) -> list[Issue]:
    """Apply configured final issue filtering without hiding filter failures."""
    final_issues = session.issues
    if enable_fp_filtering:
        try:
            final_issues = filter_issues(final_issues)
            final_issues = deduplicate_issues(final_issues)
        except (TypeError, ValueError, KeyError, AttributeError):
            logger.warning("FP filtering/deduplication failed, using raw issues", exc_info=True)
            session.record_fallback_event(fp_filtering_event())
            final_issues = session.issues
    return final_issues
