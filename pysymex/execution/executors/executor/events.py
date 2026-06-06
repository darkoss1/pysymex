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

"""Executor-local stats emission.

``emit_event`` forwards counters to the shared :class:`~pysymex.stats.registry.StatsRegistry`
so scans can record solver and path-exploration telemetry without importing
heavy stats types into hot VM loops.
"""

from __future__ import annotations

from pysymex.stats.registry import StatsRegistry
from pysymex.stats.types import EventType, Metadata

_stats_registry = StatsRegistry()


def emit_event(
    event_type: EventType,
    value: float = 0.0,
    metadata: Metadata | None = None,
) -> None:
    """Emit one stats event through the process-wide registry.

    Args:
        event_type: Counter or gauge identifier defined in ``EventType``.
        value: Numeric payload (typically ``1.0`` for increment-style events).
        metadata: Optional structured metadata attached to the event.
    """
    if not _stats_registry.running:
        return
    _stats_registry.emit(event_type, value, metadata)
