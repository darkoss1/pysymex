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

"""Statistics collection package for pysymex.

Provides a global registry for registering metric collectors and sinks,
and functions for emitting events and managing the background flushing thread.
"""

from __future__ import annotations

from .registry import StatsRegistry
from .types import EventType, Event, Metadata
from .collectors.perf import PerfCollector
from .collectors.smt import SmtCollector
from .sinks.sqlite import SQLiteSink
from .sinks.console import ConsoleSink


_STATS_REGISTRY = StatsRegistry()
registry: StatsRegistry = _STATS_REGISTRY

_STATS_REGISTRY.register_collector(PerfCollector())
_STATS_REGISTRY.register_collector(SmtCollector())

# NOTE: ConsoleSink is NOT registered here by default.  The CLI registers
# it only when ``--stats`` is passed, so stats output does not appear
# unless explicitly requested.  Other sinks (e.g. SQLiteSink) can still
# be registered unconditionally if needed.


def enable_console_sink() -> None:
    """Register the Rich-powered ConsoleSink for live streaming stats."""
    if any(isinstance(sink, ConsoleSink) for sink in _STATS_REGISTRY.sinks):
        return
    _STATS_REGISTRY.register_sink(ConsoleSink())


def emit(event_type: EventType, value: float = 0.0, metadata: Metadata | None = None) -> None:
    """Facade for lock-free event emission."""
    _STATS_REGISTRY.emit(event_type, value, metadata)


def start() -> None:
    """Start the PSS background flusher."""
    _STATS_REGISTRY.start()


def stop() -> None:
    """Stop the PSS background flusher."""
    _STATS_REGISTRY.stop()


__all__ = [
    "registry",
    "emit",
    "start",
    "stop",
    "enable_console_sink",
    "EventType",
    "Event",
    "SQLiteSink",
    "ConsoleSink",
]
