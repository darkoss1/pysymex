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

"""Scan tracing adapter.

Owns the scan-specific adapter between an execution configuration, a
:class:`~pysymex._internal.execution.executors.core.SymbolicExecutor`, and the optional tracing
telemetry stack. The scanner calls this module when trace collection is requested;
execution modules own VM semantics, while this module owns tracing session setup.
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING, Protocol

from pysymex._internal.config.environment import read_trace_environment

if TYPE_CHECKING:
    from pathlib import Path

    from pysymex._internal.config.execution.settings import ExecutionConfig
    from pysymex._internal.execution.executors.core import SymbolicExecutor


class ScanTracer(Protocol):
    """Trace manager installed on a scan executor."""

    def install(self, executor: SymbolicExecutor) -> None:
        """Install tracing hooks onto the executor."""
        ...

    def end_session(self) -> object:
        """End the current tracing session and return its payload."""
        ...


def install_scan_tracer(
    *,
    trace_enabled: bool | None,
    trace_output_dir: str | None,
    trace_verbosity: str,
    file_path: Path,
    config: ExecutionConfig,
    executor: SymbolicExecutor,
) -> ScanTracer | None:
    """Install a scan execution tracer when tracing is enabled.

    Side Effects:
        Starts a tracing session and installs executor hooks when tracing is active.
    """
    if trace_enabled is False:
        return None
    if trace_enabled is None and not read_trace_environment().enabled:
        return None

    from pysymex._internal.config.tracing.settings import TracerConfig, VerbosityLevel
    from pysymex._internal.tracing.tracer.core import ExecutionTracer

    verbosity_value = trace_verbosity.strip().lower()
    verbosity = {
        "quiet": VerbosityLevel.QUIET,
        "delta_only": VerbosityLevel.DELTA_ONLY,
        "full": VerbosityLevel.FULL,
    }.get(verbosity_value, VerbosityLevel.DELTA_ONLY)

    cfg_overrides: dict[str, object] = {"verbosity": verbosity}
    if trace_enabled is not None:
        cfg_overrides["enabled"] = trace_enabled
    if trace_output_dir:
        cfg_overrides["output_dir"] = trace_output_dir

    tracer_cfg = TracerConfig.from_env(**cfg_overrides)
    if not tracer_cfg.enabled:
        return None

    tracer = ExecutionTracer(config=tracer_cfg)
    tracer.start_session(
        func_name=f"scan:{file_path.stem}",
        signature_str="(module-scan)",
        initial_args={},
        config_snapshot=dataclasses.asdict(config),
        source_file=str(file_path),
    )
    tracer.install(executor)
    return tracer
