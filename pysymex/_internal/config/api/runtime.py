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

"""Typed configuration keyword contracts for public runtime API calls."""

from __future__ import annotations

from typing import TYPE_CHECKING, TypedDict

if TYPE_CHECKING:
    from pysymex._internal.execution.scan.types import ScanExecutionObserver
    from pysymex._internal.scanner.protocols import ScanReporter


class ScanFileConfigKwargs(TypedDict, total=False):
    """Configuration keyword arguments accepted by public single-file scans."""

    verbose: bool
    max_paths: int | None
    timeout: float | None
    max_depth: int | None
    auto_tune: bool
    reporter: ScanReporter | None
    use_sandbox: bool
    no_cache: bool
    max_iterations: int | None
    trace_enabled: bool | None
    trace_output_dir: str | None
    trace_verbosity: str
    enable_fp_filtering: bool
    detect_overflow: bool
    execution_observer: ScanExecutionObserver | None
    confirm_issues: bool
    replay_timeout: float
    function_filter: str | None


class ScanDirectoryConfigKwargs(TypedDict, total=False):
    """Configuration keyword arguments accepted by public directory scans."""

    pattern: str
    verbose: bool
    max_paths: int | None
    timeout: float | None
    max_depth: int | None
    workers: int | None
    auto_tune: bool
    reporter: ScanReporter | None
    use_sandbox: bool
    no_cache: bool
    max_iterations: int | None
    trace_enabled: bool | None
    trace_output_dir: str | None
    trace_verbosity: str
    enable_fp_filtering: bool
    detect_overflow: bool
    function_filter: str | None


class ScanPathConfigKwargs(ScanDirectoryConfigKwargs, total=False):
    """Configuration keyword arguments accepted by public file-or-directory scans."""

    execution_observer: ScanExecutionObserver | None
    confirm_issues: bool
    replay_timeout: float
