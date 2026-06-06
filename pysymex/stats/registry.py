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

"""Central stats registry and background flusher infrastructure."""

from __future__ import annotations

import collections
from pysymex.logger import get_logger
import os
import threading
import time

from .collectors.base import MetricCollector
from .sinks.base import StatsSink
from .types import Event, EventType, Metadata, MetricValue

logger = get_logger(__name__)


class StatsRegistry:
    """Central registry and background flusher for the Distributed Statistics System (PSS)."""

    instance: StatsRegistry | None = None
    lock = threading.Lock()

    def __new__(cls, *args: object, **kwargs: object) -> StatsRegistry:
        """Construct the single global StatsRegistry singleton instance.

        Args:
            *args (object): Positional arguments.
            **kwargs (object): Keyword arguments.

        Returns:
            StatsRegistry: The singleton StatsRegistry instance.
        """
        _ = args, kwargs
        with cls.lock:
            if cls.instance is None:
                cls.instance = super().__new__(cls)
                cls.instance._init()
            return cls.instance

    def _init(self) -> None:
        """Initialize the StatsRegistry internal stats, buffers, collectors, sinks, and threading controls."""
        self._buffers: list[collections.deque[Event]] = []
        self._buffers_lock = threading.Lock()
        self._local = threading.local()
        self.collectors: list[MetricCollector] = []
        self.sinks: list[StatsSink] = []
        self.running = False
        self.flusher_thread: threading.Thread | None = None
        self._flush_interval = 0.5
        self._last_inline_flush = 0.0
        self.global_metrics: dict[str, MetricValue] = {}

    def get_buffer(self) -> collections.deque[Event]:
        """Get the thread-local statistics event buffer, creating it if it doesn't already exist.

        Returns:
            collections.deque[Event]: The thread-local double-ended queue event buffer.
        """
        if not hasattr(self._local, "buffer"):
            new_buffer: collections.deque[Event] = collections.deque()
            self._local.buffer = new_buffer
            with self._buffers_lock:
                self._buffers.append(new_buffer)
        return self._local.buffer

    def register_collector(self, collector: MetricCollector) -> None:
        """Register a new Metric Collector."""
        self.collectors.append(collector)
        self.global_metrics.update(collector.get_metrics())

    def register_sink(self, sink: StatsSink) -> None:
        """Register a new Stats Sink."""
        self.sinks.append(sink)

    def _clear_buffers(self) -> None:
        """Discard events emitted before the current stats collection window."""
        with self._buffers_lock:
            for buffer in self._buffers:
                buffer.clear()

    def _reset_collectors(self) -> None:
        """Reset collector state and rebuild the global metrics snapshot."""
        self.global_metrics = {}
        for collector in self.collectors:
            collector.reset()
            self.global_metrics.update(collector.get_metrics())

    def emit(self, event_type: EventType, value: float, metadata: Metadata | None = None) -> None:
        """Lock-free, thread-local event emission for zero-impact instrumentation."""
        buffer = self.get_buffer()
        buffer.append(Event(event_type, value, metadata=metadata or {}))
        if self.running and self.flusher_thread is None:
            now = time.monotonic()
            if now - self._last_inline_flush >= self._flush_interval:
                self._last_inline_flush = now
                self.flush()

    def start(self) -> None:
        """Start statistics collection and the background flusher thread.

        On Windows, keep collection single-threaded and flush at stop. Z3 can
        execute long native checks while releasing the GIL; running the stats
        flusher in a parallel Python thread during those checks has triggered
        process-fatal access violations in stress scans.
        """
        with self.lock:
            if self.running:
                return
            self._clear_buffers()
            self._reset_collectors()
            self.running = True
            self._last_inline_flush = 0.0
            for sink in self.sinks:
                try:
                    sink.start()
                except Exception as e:
                    logger.error(f"Sink {sink} failed to start: {e}")
            if os.name == "nt":
                self.flusher_thread = None
                return
            self.flusher_thread = threading.Thread(
                target=self._flush_loop, daemon=True, name="StatsFlusher"
            )
            self.flusher_thread.start()

    def stop(self) -> None:
        """Stop the background flusher thread and flush remaining events."""
        with self.lock:
            if self.running:
                self.running = False
                if self.flusher_thread:
                    self.flusher_thread.join(timeout=2.0)
                self.flush(force_write=True)
                for sink in self.sinks:
                    try:
                        sink.stop()
                    except Exception as e:
                        logger.error(f"Sink {sink} failed to stop: {e}")

    def _flush_loop(self) -> None:
        """Periodic loop to flush events from thread-local buffers."""
        while self.running:
            time.sleep(self._flush_interval)
            self.flush()

    def flush(self, force_write: bool = False) -> None:
        """Manually flush all events across thread-local buffers, passing them to collectors and sinks."""
        events_to_process: list[Event] = []

        with self._buffers_lock:
            for buf in self._buffers:
                while buf:
                    try:
                        events_to_process.append(buf.popleft())
                    except IndexError:
                        break

        if not events_to_process and not force_write:
            return

        if events_to_process:
            for collector in self.collectors:
                collector.process(events_to_process)
                self.global_metrics.update(collector.get_metrics())

        for sink in self.sinks:
            try:
                sink.write(self.global_metrics)
            except Exception as e:
                logger.error(f"Sink {sink} failed to write metrics: {e}")
