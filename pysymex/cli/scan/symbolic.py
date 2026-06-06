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

"""Symbolic scan handler."""

from __future__ import annotations

import argparse
import time
from pathlib import Path
from typing import TYPE_CHECKING

from pysymex.cli.output import emit_cli_output, print_cli_error
from pysymex.cli.scan.shared import (
    IndexableObjectSequence,
    call_with_supported_kwargs,
    publish_scan_stats_if_requested,
    stop_stats_if_requested,
    typed_scan_results,
)
from pysymex.logger import get_logger

if TYPE_CHECKING:
    from pysymex.scanner.types import ScanResult

_Namespace = argparse.Namespace
logger = get_logger(__name__)


def handle_symbolic_scan(args: _Namespace, path: Path, start_time: float) -> int:
    """Handle the default *symbolic* analysis mode.

    Delegates to :func:`pysymex.scanner.scan_file` or
    :func:`pysymex.scanner.scan_directory` depending on whether
    *path* is a file or directory.

    Args:
        args: Parsed CLI namespace.
        path: Target file or directory.
        start_time: Epoch timestamp from scan start.

    Returns:
        ``1`` if issues were found, ``0`` otherwise.
    """
    deterministic_mode = args.deterministic or path.is_file()
    use_sandbox = not getattr(args, "no_sandbox", False)
    if getattr(args, "visualize", False):
        from pysymex.reporting.realtime import run_realtime_scan

        logger.verbose("Symbolic scan starting realtime mode path=%s", path)
        results = run_realtime_scan(
            path,
            recursive=args.recursive,
            max_paths=args.max_paths,
            timeout=args.timeout,
            auto_tune=args.auto,
            use_sandbox=use_sandbox,
            deterministic_mode=deterministic_mode,
            random_seed=args.seed,
            no_cache=getattr(args, "no_cache", False),
            max_iterations=getattr(args, "max_iterations", 0),
            trace_enabled=args.trace,
            trace_output_dir=args.trace_output_dir,
            trace_verbosity=args.trace_verbosity,
        )
    else:
        from pysymex.cli.reporter import ConsoleScanReporter
        from pysymex.scanner.directory import scan_directory
        from pysymex.scanner.file import scan_file

        show_stats = getattr(args, "stats", False)
        reporter = ConsoleScanReporter(show_stats=show_stats) if args.verbose else None
        logger.verbose("Symbolic scan started path=%s deterministic=%s", path, deterministic_mode)

        results: list["ScanResult"]
        if path.is_file():
            raw_result = call_with_supported_kwargs(
                scan_file,
                path,
                verbose=args.verbose,
                max_paths=args.max_paths,
                timeout=args.timeout,
                auto_tune=args.auto,
                reporter=reporter,
                use_sandbox=use_sandbox,
                deterministic_mode=deterministic_mode,
                random_seed=args.seed,
                no_cache=getattr(args, "no_cache", False),
                max_iterations=getattr(args, "max_iterations", 0),
                trace_enabled=args.trace,
                trace_output_dir=args.trace_output_dir,
                trace_verbosity=args.trace_verbosity,
            )
            results = typed_scan_results([raw_result])
        else:
            from pysymex.scanner.types import ScanResult as _ScanResult

            pattern = getattr(args, "_scan_glob_pattern", None)
            if not isinstance(pattern, str):
                pattern = "**/*.py" if args.recursive else "*.py"
            raw_results = call_with_supported_kwargs(
                scan_directory,
                path,
                pattern=pattern,
                verbose=args.verbose,
                max_paths=args.max_paths,
                timeout=args.timeout,
                workers=args.workers,
                auto_tune=args.auto,
                reporter=reporter,
                use_sandbox=use_sandbox,
                deterministic_mode=args.deterministic,
                random_seed=args.seed,
                no_cache=getattr(args, "no_cache", False),
                max_iterations=getattr(args, "max_iterations", 0),
                trace_enabled=args.trace,
                trace_output_dir=args.trace_output_dir,
                trace_verbosity=args.trace_verbosity,
            )
            if isinstance(raw_results, IndexableObjectSequence):
                results = []
                for index in range(len(raw_results)):
                    item = raw_results[index]
                    if isinstance(item, _ScanResult):
                        results.append(item)
            else:
                results = []

    if not results and path.is_file():
        logger.warning("Symbolic scan produced no result for file %s", path)
        stop_stats_if_requested(args)
        print_cli_error(f"No valid scan results were produced for: {path}")
        return 1

    total_issues = sum(len(r.issues) for r in results)
    has_errors = any(r.error is not None for r in results)
    has_degraded_analyses = any(r.degraded_passes for r in results)
    duration = time.time() - start_time

    try:
        if args.format == "json":
            from pysymex.cli.formatters import get_formatter

            formatter = get_formatter(args.format)
            output = formatter.format_symbolic(
                results, total_issues, duration, args.reproduce, getattr(args, "stats", False)
            )
        elif args.format == "sarif":
            from pysymex.cli.formatters import get_formatter

            formatter = get_formatter(args.format)
            output = formatter.format_symbolic(
                results, total_issues, duration, args.reproduce, getattr(args, "stats", False)
            )
        else:
            from pysymex.cli.formatters import get_formatter

            formatter = get_formatter(args.format)
            show_stats = getattr(args, "stats", False)
            output = formatter.format_symbolic(
                results, total_issues, duration, args.reproduce, show_stats
            )

        publish_scan_stats_if_requested(args, results)
        stop_stats_if_requested(args)
        emit_cli_output(output, output_path=args.output, verbose=args.verbose)
    except Exception as e:
        logger.warning("Symbolic scan report generation failed for %s", path, exc_info=True)
        stop_stats_if_requested(args)
        print_cli_error(f"Internal error during report generation: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1

    return 1 if total_issues > 0 or has_errors or has_degraded_analyses else 0


__all__ = ["handle_symbolic_scan"]
