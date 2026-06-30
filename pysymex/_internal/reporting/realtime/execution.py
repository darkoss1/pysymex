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

"""Canonical scanner adapter for realtime visualisation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.config.defaults import DEFAULT_TRACE_VERBOSITY
from pysymex._internal.scanner.file import scan_file

if TYPE_CHECKING:
    from pathlib import Path

    from pysymex._internal.reporting.realtime.plugin import RealtimePlugin
    from pysymex._internal.scanner.types import ScanResult


def execute_realtime_file(
    file_path: Path,
    max_paths: int | None,
    timeout: float | None,
    vis_plugin: RealtimePlugin,
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
) -> ScanResult:
    """Scan one file through the canonical scanner while updating live state."""
    return scan_file(
        file_path,
        max_paths=max_paths,
        max_depth=max_depth,
        timeout=timeout,
        auto_tune=auto_tune,
        use_sandbox=use_sandbox,
        no_cache=no_cache,
        max_iterations=max_iterations,
        trace_enabled=trace_enabled,
        trace_output_dir=trace_output_dir,
        trace_verbosity=trace_verbosity,
        detect_overflow=detect_overflow,
        execution_observer=vis_plugin,
    )
