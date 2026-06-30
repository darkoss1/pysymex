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

"""Convenience factory function for attaching the tracer to an executor."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.tracing.tracer.core import ExecutionTracer

if TYPE_CHECKING:
    from pathlib import Path

    from pysymex._internal.config.tracing.settings import TracerConfig
    from pysymex._internal.execution.executors.core import SymbolicExecutor


def attach_tracer(
    executor: SymbolicExecutor,
    func_name: str,
    signature_str: str = "",
    initial_args: dict[str, str] | None = None,
    config: TracerConfig | None = None,
    source_file: str = "<unknown>",
) -> tuple[ExecutionTracer, Path | None]:
    """Create, start, and install a tracer onto *executor* in one call.

    This is the recommended entry point for most use cases.  The caller is
    responsible for calling :meth:`ExecutionTracer.end_session` after the
    analysis completes (or using the tracer as a context manager).

    Args:
        executor:       The executor to trace.
        func_name:      Qualified name of the function under analysis.
        signature_str:  Human-readable signature string.
        initial_args:   ``{param_name: type_string}`` mapping.
        config:         Tracer configuration.  Defaults to :class:`TracerConfig`.
        source_file:    Path to the source file.

    Returns:
        ``(tracer, trace_path)`` tuple.  ``trace_path`` is ``None`` if the
        tracer is disabled.

    """
    tracer = ExecutionTracer(config=config)
    trace_path = tracer.start_session(
        func_name=func_name,
        signature_str=signature_str,
        initial_args=initial_args or {},
        source_file=source_file,
    )
    tracer.install(executor)
    return tracer, trace_path
