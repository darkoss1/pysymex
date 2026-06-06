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

"""Sequence numbering and buffered event writing for execution tracers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel

from pysymex.logger import get_logger
from pysymex.tracing.schemas import TracerConfig
from pysymex.tracing.tracer.helpers import TraceWriter

logger = get_logger(__name__)

if TYPE_CHECKING:
    from threading import Lock


class TracerWritingMixin:
    """Sequence allocation and JSONL write buffering behavior."""

    if TYPE_CHECKING:
        config: TracerConfig
        file: TraceWriter | None
        lock: Lock
        seq: int
        _delta_buffer: list[str]

    def _next_seq(self) -> int:
        """Return and post-increment the global sequence counter."""
        with self.lock:
            seq = self.seq
            self.seq += 1
        return seq

    def _write_event(self, event: BaseModel, *, force_flush: bool) -> None:
        """Serialise *event* to JSONL and manage the write buffer.

        Force-flush behaviour:
        * ``force_flush=True`` → append the line, then flush the entire
          buffer to disk and call ``file.flush()`` for OS-level durability.
        * ``force_flush=False`` → append to buffer; only flush if buffer
          reaches ``delta_batch_size``.

        Args:
            event:       A Pydantic model instance.
            force_flush: Whether to synchronously flush to disk.
        """
        if self.file is None:
            return
        try:
            line = event.model_dump_json()
        except Exception:
            logger.debug("Failed to serialize trace event %s", type(event).__name__, exc_info=True)
            return

        with self.lock:
            self._delta_buffer.append(line)
            if force_flush or len(self._delta_buffer) >= self.config.delta_batch_size:
                self._flush_buffer_locked()

    def _flush_buffer_locked(self) -> None:
        """Write all buffered lines to file.  Must be called under ``lock``."""
        if self.file is None or not self._delta_buffer:
            return
        try:
            self.file.write("\n".join(self._delta_buffer) + "\n")
            self.file.flush()
            self._delta_buffer.clear()
        except Exception:
            logger.debug("Failed to flush trace event buffer", exc_info=True)
            self._delta_buffer.clear()


__all__ = ["TracerWritingMixin"]
