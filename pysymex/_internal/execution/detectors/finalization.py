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

"""Final detector issue filtering for execution results."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.filter.core import filter_issues
from pysymex._internal.analysis.detectors.filter.dedup import deduplicate_issues
from pysymex._internal.execution.fallback.infrastructure import fp_filtering_event
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from pysymex._internal.analysis.detectors.detector.types import Issue
    from pysymex._internal.execution.session.state.core import ExecutionSession

logger = get_logger(__name__)


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
