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

"""Detector-query UNKNOWN fallback classification."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from pysymex._internal.execution.fallback.types import (
    FallbackEvent,
    FallbackKind,
    RiskLevel,
    SoundnessTag,
)

if TYPE_CHECKING:
    from pysymex._internal.execution.session.state.core import ExecutionSession

SOLVER_UNKNOWN_DETECTOR_QUERY_DEGRADED_PASS: Final = "solver_unknown_detector_query"


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
        ),
    )
