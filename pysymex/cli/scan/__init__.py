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

"""Scan-related CLI commands and formatters for pysymex."""

from __future__ import annotations

import argparse
import time
from collections.abc import Callable
from pathlib import Path

from pysymex.cli.output import print_cli_error
from pysymex.cli.scan.async_runner import cmd_scan_async
from pysymex.cli.scan.symbolic import handle_symbolic_scan
from pysymex.logger import get_logger
from pysymex.pathing import normalize_input_path

_Namespace = argparse.Namespace
logger = get_logger(__name__)
_GLOB_CHARS = frozenset("*?[")


def _path_has_glob(path: str) -> bool:
    """Return whether *path* contains shell glob metacharacters."""
    return any(char in path for char in _GLOB_CHARS)


def _split_glob_path(path: str) -> tuple[Path, str]:
    """Split a glob path into the concrete base directory and relative pattern."""
    parts = path.replace("\\", "/").split("/")
    for index, part in enumerate(parts):
        if _path_has_glob(part):
            base_text = "/".join(parts[:index]) or "."
            pattern = "/".join(parts[index:])
            return normalize_input_path(base_text), pattern
    return normalize_input_path(path), ""


def _resolve_scan_path(path_text: str) -> tuple[Path, str | None]:
    """Resolve a scan path, expanding literal glob arguments when the shell does not."""
    path = normalize_input_path(path_text)
    if path.exists() or not _path_has_glob(path_text):
        return path, None

    base_path, pattern = _split_glob_path(path_text)
    if not pattern or not base_path.is_dir():
        return path, None
    try:
        has_matches = any(base_path.glob(pattern))
    except (OSError, ValueError):
        return path, None
    if not has_matches:
        return path, None
    return base_path, pattern


def cmd_scan(args: _Namespace) -> int:
    """Execute the ``scan`` sub-command."""
    path, glob_pattern = _resolve_scan_path(str(args.path))
    if glob_pattern is not None:
        setattr(args, "_scan_glob_pattern", glob_pattern)
    if not path.exists():
        logger.warning("Scan CLI path does not exist: %s", path)
        print_cli_error(f"Path not found: {path}")
        return 1
    if args.verbose:
        print(f"[SCAN] Scanning: {path} (symbolic execution)")
    stop_stats: Callable[[], None] | None = None
    if getattr(args, "stats", False):
        from pysymex.stats import enable_console_sink, start, stop

        enable_console_sink()
        stop_stats = stop
        start()
    start_time = time.time()
    try:
        logger.verbose("Scan CLI starting symbolic scan for %s", path)
        return handle_symbolic_scan(args, path, start_time)
    finally:
        if stop_stats is not None and not getattr(args, "_stats_stopped", False):
            stop_stats()


__all__ = ["cmd_scan", "cmd_scan_async"]
