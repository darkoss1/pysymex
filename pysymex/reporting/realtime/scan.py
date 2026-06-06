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

"""Realtime scan runner."""

from __future__ import annotations

from pathlib import Path

from pysymex.config.defaults import DEFAULT_SCAN_RANDOM_SEED, DEFAULT_TRACE_VERBOSITY
from pysymex.reporting.realtime.execution import execute_realtime_file
from pysymex.reporting.realtime.graph import (
    initialize_graph,
    mark_file_active,
    mark_file_done,
    select_scan_files,
)
from pysymex.reporting.realtime.plugin import RealtimeVisualizationPlugin
from pysymex.reporting.realtime.server import shutdown_realtime_server, start_realtime_server
from pysymex.scanner.types import ScanResult


def run_realtime_scan(
    path: Path,
    recursive: bool = True,
    max_paths: int = 1000,
    timeout: float = 60.0,
    *,
    auto_tune: bool = False,
    use_sandbox: bool = True,
    deterministic_mode: bool = False,
    random_seed: int = DEFAULT_SCAN_RANDOM_SEED,
    no_cache: bool = False,
    max_iterations: int = 0,
    trace_enabled: bool | None = None,
    trace_output_dir: str | None = None,
    trace_verbosity: str = DEFAULT_TRACE_VERBOSITY,
) -> list[ScanResult]:
    """Run a scan with a live D3 network-map visualiser."""
    files, root_dir = select_scan_files(path, recursive)
    if not files:
        return []

    dir_set = initialize_graph(files, root_dir)
    server = start_realtime_server()
    results: list[ScanResult] = []
    vis_plugin = RealtimeVisualizationPlugin()

    for file_path in files:
        mark_file_active(file_path, root_dir, dir_set)
        result = execute_realtime_file(
            file_path,
            max_paths,
            timeout,
            vis_plugin,
            auto_tune=auto_tune,
            use_sandbox=use_sandbox,
            deterministic_mode=deterministic_mode,
            random_seed=random_seed,
            no_cache=no_cache,
            max_iterations=max_iterations,
            trace_enabled=trace_enabled,
            trace_output_dir=trace_output_dir,
            trace_verbosity=trace_verbosity,
        )
        results.append(result)
        mark_file_done(
            file_path,
            root_dir,
            dir_set,
            len(result.issues),
            has_error=result.error is not None,
            is_degraded=bool(result.degraded_passes),
        )

    shutdown_realtime_server(server)
    return results


__all__ = ["run_realtime_scan"]
