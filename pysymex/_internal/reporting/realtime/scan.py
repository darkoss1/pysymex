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

from collections.abc import Callable
from typing import TYPE_CHECKING

from pysymex._internal.config.defaults import DEFAULT_TRACE_VERBOSITY
from pysymex._internal.reporting.realtime.execution import execute_realtime_file
from pysymex._internal.reporting.realtime.graph import (
    initialize_graph,
    mark_file_active,
    mark_file_done,
    select_scan_files,
)
from pysymex._internal.reporting.realtime.plugin import RealtimePlugin
from pysymex._internal.reporting.realtime.server import (
    shutdown_realtime_server,
    start_realtime_server,
)

if TYPE_CHECKING:
    from pathlib import Path

    from pysymex._internal.scanner.types import ScanResult

UrlOpener = Callable[[str], object]
MessageSink = Callable[[str], None]


def run_realtime_scan(
    path: Path,
    max_paths: int | None = None,
    timeout: float | None = None,
    *,
    max_depth: int | None = None,
    auto_tune: bool = True,
    use_sandbox: bool = True,
    no_cache: bool = False,
    max_iterations: int | None = None,
    trace_enabled: bool | None = None,
    trace_output_dir: str | None = None,
    trace_verbosity: str = DEFAULT_TRACE_VERBOSITY,
    detect_overflow: bool = False,
    open_url: UrlOpener | None = None,
    message_sink: MessageSink | None = None,
    shutdown_delay_seconds: float = 120.0,
) -> list[ScanResult]:
    """Run a scan with a live D3 network-map visualiser."""
    files, root_dir = select_scan_files(path)
    if not files:
        return []

    dir_set = initialize_graph(files, root_dir)
    server = start_realtime_server(open_url=open_url, message_sink=message_sink)
    results: list[ScanResult] = []
    vis_plugin = RealtimePlugin()

    try:
        for file_path in files:
            mark_file_active(file_path, root_dir, dir_set)
            result = execute_realtime_file(
                file_path,
                max_paths,
                timeout,
                vis_plugin,
                max_depth=max_depth,
                auto_tune=auto_tune,
                use_sandbox=use_sandbox,
                no_cache=no_cache,
                max_iterations=max_iterations,
                trace_enabled=trace_enabled,
                trace_output_dir=trace_output_dir,
                trace_verbosity=trace_verbosity,
                detect_overflow=detect_overflow,
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
            if result.error and "KeyboardInterrupt" in result.error:
                break
    except KeyboardInterrupt:
        pass

    shutdown_realtime_server(
        server,
        message_sink=message_sink,
        delay_seconds=shutdown_delay_seconds,
    )
    return results
