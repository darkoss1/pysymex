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

import collections
import threading
import time
import logging

from .types import Event, EventType, Metadata, MetricValue
from .collectors.base import MetricCollector
from .sinks.base import StatsSink

logger = logging.getLogger(__name__)


class StatsRegistry:
    """Central registry and background flusher for the Distributed Statistics System (PSS)."""

    _instance: StatsRegistry | None = None
    _lock = threading.Lock()

    def __new__(cls, *args: object, **kwargs: object) -> StatsRegistry:
        _ = args, kwargs
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._init()
            return cls._instance

    def _init(self) -> None:
        self._buffers: list[collections.deque[Event]] = []
        self._buffers_lock = threading.Lock()
        self._local = threading.local()
        self._collectors: list[MetricCollector] = []
        self._sinks: list[StatsSink] = []
        self._running = False
        self._flusher_thread: threading.Thread | None = None
        self._flush_interval = 0.5
        self._global_metrics: dict[str, MetricValue] = {}

    def _get_buffer(self) -> collections.deque[Event]:
        if not hasattr(self._local, "buffer"):
            new_buffer: collections.deque[Event] = collections.deque()
            self._local.buffer = new_buffer
            with self._buffers_lock:
                self._buffers.append(new_buffer)
        return self._local.buffer

    def register_collector(self, collector: MetricCollector) -> None:
        """Register a new Metric Collector."""
        self._collectors.append(collector)
        self._global_metrics.update(collector.get_metrics())

    def register_sink(self, sink: StatsSink) -> None:
        """Register a new Stats Sink."""
        self._sinks.append(sink)

    def emit(self, event_type: EventType, value: float, metadata: Metadata | None = None) -> None:
        """Lock-free, thread-local event emission for zero-impact instrumentation."""
        buffer = self._get_buffer()
        buffer.append(Event(event_type, value, metadata=metadata or {}))

    def start(self) -> None:
        """Start the background flusher thread."""
        with self._lock:
            if not self._running:
                self._running = True
                self._flusher_thread = threading.Thread(
                    target=self._flush_loop, daemon=True, name="StatsFlusher"
                )
                self._flusher_thread.start()

    def stop(self) -> None:
        """Stop the background flusher thread and flush remaining events."""
        with self._lock:
            if self._running:
                self._running = False
                if self._flusher_thread:
                    self._flusher_thread.join(timeout=2.0)
                self.flush()
                for sink in self._sinks:
                    try:
                        sink.write(self._global_metrics)
                    except Exception as e:
                        logger.error(f"Sink {sink} failed to write final metrics: {e}")

    def _flush_loop(self) -> None:
        """Periodic loop to flush events from thread-local buffers."""
        while self._running:
            time.sleep(self._flush_interval)
            self.flush()

    def flush(self) -> None:
        """Manually flush all events across thread-local buffers, passing them to collectors and sinks."""
        events_to_process: list[Event] = []

        with self._buffers_lock:
            for buf in self._buffers:
                while buf:
                    try:
                        events_to_process.append(buf.popleft())
                    except IndexError:
                        break

        if not events_to_process:
            return

        for collector in self._collectors:
            collector.process(events_to_process)
            self._global_metrics.update(collector.get_metrics())

        for sink in self._sinks:
            try:
                sink.write(self._global_metrics)
            except Exception as e:
                logger.error(f"Sink {sink} failed to write metrics: {e}")
