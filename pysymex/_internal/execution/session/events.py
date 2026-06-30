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

"""Observer and source-line helpers for execution-session telemetry."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, TypeVar, overload

from pysymex._internal.execution.detectors.telemetry import DetectorQueryEvent
from pysymex._internal.execution.fallback.types import FallbackEvent
from pysymex._internal.execution.feasibility.telemetry import PathFeasibilityEvent
from pysymex._internal.execution.scheduling.telemetry import SchedulerEvent

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from pysymex._internal.logging.logger import PysymexLogger

ResolvableSessionEvent = FallbackEvent | DetectorQueryEvent | PathFeasibilityEvent | SchedulerEvent
EventT = TypeVar("EventT")


def add_unique_observer(
    observers: list[Callable[[EventT], None]],
    observer: Callable[[EventT], None],
) -> None:
    """Register ``observer`` once for a session telemetry list."""
    if observer not in observers:
        observers.append(observer)


def notify_observers(
    observers: list[Callable[[EventT], None]],
    event: EventT,
    *,
    failure_message: str,
    logger: PysymexLogger,
) -> None:
    """Notify observers while preserving execution when an observer fails."""
    for observer in observers:
        try:
            observer(event)
        except Exception:
            logger.debug(failure_message, exc_info=True)


@overload
def event_with_resolved_line(
    event: FallbackEvent,
    pc_to_line: Mapping[int, int],
) -> FallbackEvent: ...


@overload
def event_with_resolved_line(
    event: DetectorQueryEvent,
    pc_to_line: Mapping[int, int],
) -> DetectorQueryEvent: ...


@overload
def event_with_resolved_line(
    event: PathFeasibilityEvent,
    pc_to_line: Mapping[int, int],
) -> PathFeasibilityEvent: ...


@overload
def event_with_resolved_line(
    event: SchedulerEvent,
    pc_to_line: Mapping[int, int],
) -> SchedulerEvent: ...


def event_with_resolved_line(
    event: ResolvableSessionEvent,
    pc_to_line: Mapping[int, int],
) -> ResolvableSessionEvent:
    """Attach a source line to a telemetry event when the session can resolve it."""
    if event.line_number is not None or event.pc is None:
        return event
    line_number = pc_to_line.get(event.pc)
    if line_number is None:
        return event
    return replace(event, line_number=line_number)
