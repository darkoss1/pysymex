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

"""Scanner execution tracing setup.

Part of the telemetry and diagnostics layer. Sets up and configures the
telemetry tracing session on the symbolic executor VM, saving execution steps.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Protocol

from pysymex.config.environment import read_trace_environment
from pysymex.execution.config.settings import ExecutionConfig
from pysymex.execution.executors import SymbolicExecutor


class ScannerTracer(Protocol):
    """Protocol representing a trace manager that monitors symbolic execution sessions.

    Maintains hooks to record VM steps, path branch forks, and solver calls.
    """

    def install(self, executor: SymbolicExecutor) -> None:
        """Install this tracer onto a symbolic executor instance.

        Args:
            executor: The symbolic executor instance to monitor.
        """
        ...

    def end_session(self) -> object:
        """End the current tracing session and retrieve the session payload.

        Returns:
            The trace session report or state payload dict.
        """
        ...


def install_scanner_tracer(
    *,
    trace_enabled: bool | None,
    trace_output_dir: str | None,
    trace_verbosity: str,
    file_path: Path,
    config: ExecutionConfig,
    executor: SymbolicExecutor,
) -> ScannerTracer | None:
    """Install a scanner execution tracer when tracing is enabled.

    Configures config overrides, creates the tracer instance, starts a tracing session,
    and installs it on the executor.

    Args:
        trace_enabled: Config override to toggle tracing.
        trace_output_dir: Directory where traces are exported.
        trace_verbosity: Verbosity level string (e.g. ``"quiet"``, ``"delta_only"``, ``"full"``).
        file_path: Path to the target source file.
        config: baseline executor configuration.
        executor: The active executor to hook.

    Returns:
        The installed tracer instance, or ``None`` if tracing is disabled.

    Side Effects:
        Hooks the symbolic executor to monitor states and registers tracer telemetry.
    """
    if trace_enabled is False:
        return None
    if trace_enabled is None and not read_trace_environment().enabled:
        return None

    from pysymex.tracing.schemas import TracerConfig, VerbosityLevel
    from pysymex.tracing.tracer import ExecutionTracer

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
