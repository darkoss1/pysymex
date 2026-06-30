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

"""Model sink-event issue conversion."""

from __future__ import annotations

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.models.contracts.results import SideEffects


def issue_from_sink_event(effect: object, *, pc: int) -> Issue | None:
    """Create a runtime issue for a critical model sink event."""
    if not SideEffects.is_sink_event(effect) or effect["severity"] != "critical":
        return None
    sink_type = effect["sink_type"]
    message = f"[{effect['source']}] Dynamic code sink reached: {sink_type}"
    return Issue(
        kind=IssueKind.RUNTIME_ERROR,
        message=message,
        pc=pc,
        detector_name="model-side-effect",
    )
