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

"""Progress-safe terminal emission."""

from __future__ import annotations

import contextlib
import threading
from typing import TextIO


class TerminalEmitter:
    """Single terminal write pipeline for diagnostics and progress output."""

    def __init__(self, stream: TextIO) -> None:
        """Initialize a single terminal write pipeline emitter.

        Args:
            stream: The TextIO stream (e.g. sys.stdout) to write diagnostic
                and progress output to.

        """
        self._stream = stream
        self._lock = threading.Lock()
        self._progress_active = False

    def emit_line(self, line: str) -> None:
        """Write a full line without corrupting an active progress line."""
        with self._lock:
            if self._progress_active:
                self._write("\r\033[K")
                self._progress_active = False
            self._write(line + "\n")
            self._flush()

    def progress(self, current: int, total: int, message: str) -> None:
        """Render a single-line progress bar."""
        with self._lock:
            pct = (current / total * 100) if total > 0 else 0.0
            bar_width = 30
            filled = int(bar_width * current / total) if total > 0 else 0
            bar = "=" * filled + "-" * (bar_width - filled)
            suffix = f" {message}" if message else ""
            self._write(f"\r[{bar}] {pct:5.1f}%{suffix}")
            if current >= total:
                self._write("\n")
                self._progress_active = False
            else:
                self._progress_active = True
            self._flush()

    def _write(self, text: str) -> None:
        """Write text to the stream with fallback encoding support.

        Handles potential UnicodeEncodeError exceptions by replacing unsupported
        characters with safe fallback representations matching the stream encoding.

        Args:
            text: The text string to write.

        """
        try:
            self._stream.write(text)
        except UnicodeEncodeError:
            encoding = self._stream.encoding or "utf-8"
            fallback = text.encode(encoding, errors="replace").decode(encoding, errors="replace")
            try:
                self._stream.write(fallback)
            except (OSError, ValueError):
                return
        except (OSError, ValueError):
            return

    def _flush(self) -> None:
        """Flush the underlying stream.

        Suppresses stream failures when the stream is closed or detached.
        """
        with contextlib.suppress(OSError, ValueError):
            self._stream.flush()
