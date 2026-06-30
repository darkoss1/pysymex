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

"""Execution tracer session lifecycle methods."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, Self

from pysymex._internal.logging.root import get_logger
from pysymex._internal.tracing.schemas.events import SystemContextEvent
from pysymex._internal.tracing.tracer.serialization import TraceSerialization, TraceWriter

logger = get_logger(__name__)

if TYPE_CHECKING:
    from threading import Lock

    from pysymex._internal.config.tracing.settings import TracerConfig


class _LineCache(Protocol):
    """Protocol defining source code line caching interfaces."""

    def getline(self, filename: str, lineno: int) -> str:
        """Retrieve a specific line from a file cache.

        Args:
            filename: Absolute path to the source file.
            lineno: The 1-based line number to extract.

        Returns:
            The requested source line as a string.

        """
        ...


class TracerSessionMixin:
    """Session lifecycle behavior for execution tracers."""

    if TYPE_CHECKING:
        config: TracerConfig
        file: TraceWriter | None
        _trace_path: Path | None
        lock: Lock
        _linecache: _LineCache
        _session_source_file: str

        def _write_event(self, event: object, *, force_flush: bool) -> None:
            """Write a telemetry event to the session output stream.

            Args:
                event: The event payload model to serialize and write.
                force_flush: If True, forces flushing buffered lines directly to disk.

            """
            ...

        def _flush_buffer_locked(self) -> None:
            """Flush buffered events to the file stream.

            Must be invoked while holding the session lock.
            """
            ...

    def start_session(
        self,
        func_name: str,
        signature_str: str,
        initial_args: dict[str, str],
        config_snapshot: dict[str, object] | None = None,
        source_file: str = "<unknown>",
    ) -> Path:
        """Open a new trace file and write the ``system_context`` header.

        Args:
            func_name:       Qualified name of the function under analysis.
            signature_str:   String representation of the function signature.
            initial_args:    ``{parameter_name: type_string}`` mapping.
            config_snapshot: Serialised :class:`~pysymex._internal.config.execution.settings.ExecutionConfig`
                             as a plain dict, or ``None``.
            source_file:     Absolute path to the source file.

        Returns:
            The :class:`~pathlib.Path` where events will be written.

        Raises:
            RuntimeError: If a session is already active.

        """
        if self.file is not None:
            msg = "A tracing session is already active.  Call end_session() first."
            raise RuntimeError(msg)
        if not self.config.enabled:
            logger.verbose("Trace session requested while tracing is disabled")
            return Path(self.config.output_dir)

        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
        safe_name = "".join(c if c.isalnum() or c in ("_", "-") else "_" for c in func_name)
        filename = f"trace_{ts}_{safe_name}.jsonl.gz"
        out_dir = Path(self.config.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        from pysymex._internal.pathing import ensure_pysymex_gitignore

        ensure_pysymex_gitignore(out_dir)
        self._trace_path = out_dir / filename

        import gzip

        self.file = gzip.open(
            self._trace_path,
            "wt",
            encoding="utf-8",
            compresslevel=self.config.compression_level,
        )

        z3_version = "unavailable"
        try:
            import z3

            z3_version = z3.get_version_string()
        except Exception:
            logger.debug("Z3 version probe failed for trace header", exc_info=True)

        from pysymex._internal.config.defaults import VERSION

        pysymex_version = VERSION

        raw_config = config_snapshot if config_snapshot is not None else self.config.model_dump()

        header = SystemContextEvent(
            timestamp_iso=datetime.now(UTC).isoformat(),
            pysymex_version=pysymex_version,
            z3_version=z3_version,
            function_name=func_name,
            function_signature=signature_str,
            source_file=source_file,
            initial_symbolic_args=initial_args,
            tracer_config=TraceSerialization.config_snapshot(raw_config),
        )
        self._write_event(header, force_flush=True)
        self._session_source_file = source_file
        logger.info("Trace session started for %s: %s", func_name, self._trace_path)
        return self._trace_path

    def _get_source_line(self, filename: str | None, line_number: int | None) -> str | None:
        """Retrieve a specific line of source code from the cache."""
        target = filename or self._session_source_file
        if not target or not line_number:
            return None
        line = self._linecache.getline(target, line_number)
        return line.strip() if line else None

    def end_session(self) -> Path | None:
        """Flush all buffered events and close the trace file.

        Returns:
            The :class:`~pathlib.Path` to the completed trace file, or
            ``None`` if the tracer is disabled or no session was active.

        """
        if not self.config.enabled or self.file is None:
            return self._trace_path
        with self.lock:
            self._flush_buffer_locked()
            try:
                self.file.flush()
                self.file.close()
            except Exception:
                logger.debug("Failed to close trace file cleanly", exc_info=True)
            finally:
                self.file = None
        logger.info("Trace session ended: %s", self._trace_path)
        return self._trace_path

    def __enter__(self) -> Self:
        """Enter the trace session context manager.

        Returns:
            The active session instance.

        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Exit the trace session context manager.

        Ensures that all buffered telemetry events are flushed and the output
        gzip file is closed, even if an exception was raised.

        Args:
            exc_type: The exception class if raised, or None.
            exc_val: The exception instance if raised, or None.
            exc_tb: The traceback object if raised, or None.

        """
        if exc_type is not None:
            try:
                self.end_session()
            except Exception:
                logger.debug("Failed to end trace session during exception cleanup", exc_info=True)
        else:
            self.end_session()
