# pysymex: Python Symbolic Execution & Formal Verification
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

from __future__ import annotations

from .registry import StatsRegistry
from .types import EventType, Event, Metadata
from .collectors.perf import PerfCollector
from .collectors.smt import SmtCollector
from .sinks.sqlite import SQLiteSink
from .sinks.console import ConsoleSink

# Singleton Registry
_STATS_REGISTRY = StatsRegistry()
registry: StatsRegistry = _STATS_REGISTRY

# Initialize defaults
_STATS_REGISTRY.register_collector(PerfCollector())
_STATS_REGISTRY.register_collector(SmtCollector())

# Default sinks (SQLite disabled by default until user specifically turns on stats)
# We can register the console sink by default for debugging:
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


__all__ = ["registry", "emit", "start", "stop", "EventType", "Event", "SQLiteSink"]
