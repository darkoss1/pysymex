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

"""Telemetry event and observer defaults for execution sessions."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.execution.detectors.telemetry import DetectorQueryEvent
    from pysymex._internal.execution.fallback.types import FallbackEvent
    from pysymex._internal.execution.feasibility.telemetry import PathFeasibilityEvent
    from pysymex._internal.execution.scheduling.telemetry import SchedulerEvent


def default_fallback_events() -> list[FallbackEvent]:
    return []


def default_fallback_event_observers() -> list[Callable[[FallbackEvent], None]]:
    return []


def default_detector_query_event_observers() -> list[Callable[[DetectorQueryEvent], None]]:
    return []


def default_path_feasibility_event_observers() -> list[Callable[[PathFeasibilityEvent], None]]:
    return []


def default_scheduler_event_observers() -> list[Callable[[SchedulerEvent], None]]:
    return []
