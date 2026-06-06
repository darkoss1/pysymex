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

"""Async scan command handling."""

from __future__ import annotations

import argparse
import time
from pathlib import Path

from pysymex.cli.output import emit_cli_output, print_cli_error
from pysymex.cli.scan.shared import stop_stats_if_requested
from pysymex.logger import get_logger
from pysymex.pathing import normalize_input_path

_Namespace = argparse.Namespace
logger = get_logger(__name__)


async def cmd_scan_async(args: _Namespace) -> int:
    """Execute scan command using async TaskGroup-based scanner.

    Called when the user passes ``--async`` to the CLI.  Uses
    :func:`pysymex.scanner.async_scanner.scan_directory` for
    structured-concurrency scanning with graceful shutdown support.
    """
    from pysymex.core.shutdown import install_signal_handlers

    path = normalize_input_path(str(args.path))
    if not path.exists():
        logger.warning("Async scan CLI path does not exist: %s", path)
        print_cli_error(f"Path not found: {path}")
        return 1

    if args.verbose:
        print(f"[SCAN] Async scanning: {path} (symbolic execution)")

    import asyncio

    loop = asyncio.get_running_loop()
    shutdown_handle = install_signal_handlers(loop)
    try:
        start_time = time.time()
        logger.verbose("Async scan CLI starting symbolic scan for %s", path)
        return await _handle_symbolic_scan_async(args, path, start_time)
    finally:
        shutdown_handle.close()


async def _handle_symbolic_scan_async(
    args: _Namespace,
    path: Path,
    start_time: float,
) -> int:
    """Handle symbolic scan using async TaskGroup scanner."""
    import asyncio

    from pysymex.cli.reporter import ConsoleScanReporter
    from pysymex.scanner.async_scanner import scan_directory

    reporter = ConsoleScanReporter() if args.verbose else None
    deterministic_mode = args.deterministic or path.is_file()
    use_sandbox = not getattr(args, "no_sandbox", False)

    if path.is_file():
        from pysymex.scanner.file import scan_file

        result = await asyncio.to_thread(
            scan_file,
            path,
            verbose=args.verbose,
            max_paths=args.max_paths,
            timeout=args.timeout,
            auto_tune=args.auto,
            reporter=reporter,
            use_sandbox=use_sandbox,
            trace_enabled=args.trace,
            trace_output_dir=args.trace_output_dir,
            trace_verbosity=args.trace_verbosity,
            deterministic_mode=deterministic_mode,
            random_seed=args.seed,
            no_cache=getattr(args, "no_cache", False),
            max_iterations=getattr(args, "max_iterations", 0),
        )
        results = [result]
    else:
        pattern = "**/*.py" if args.recursive else "*.py"
        try:
            results = await scan_directory(
                path,
                pattern=pattern,
                verbose=args.verbose,
                max_paths=args.max_paths,
                timeout=args.timeout,
                max_concurrency=args.workers if args.workers > 0 else None,
                auto_tune=args.auto,
                use_sandbox=use_sandbox,
                deterministic_mode=args.deterministic,
                random_seed=args.seed,
                no_cache=getattr(args, "no_cache", False),
                max_iterations=getattr(args, "max_iterations", 0),
                trace_enabled=args.trace,
                trace_output_dir=args.trace_output_dir,
                trace_verbosity=args.trace_verbosity,
            )
        except ExceptionGroup as exc:
            stop_stats_if_requested(args)
            logger.error("Async symbolic scan failed for %s", path, exc_info=True)
            print_cli_error(f"Async scan failed for {len(exc.exceptions)} file(s): {path}")
            return 1

    if not results and path.is_file():
        stop_stats_if_requested(args)
        logger.warning("Async scan produced no valid scan results for %s", path)
        print_cli_error(f"No valid scan results were produced for: {path}")
        return 1

    total_issues = sum(len(r.issues) for r in results)
    has_errors = any(r.error is not None for r in results)
    has_degraded_analyses = any(r.degraded_passes for r in results)
    duration = time.time() - start_time

    from pysymex.cli.formatters import get_formatter

    formatter = get_formatter(args.format)
    show_stats = getattr(args, "stats", False)
    output = formatter.format_symbolic(results, total_issues, duration, args.reproduce, show_stats)

    stop_stats_if_requested(args)
    emit_cli_output(output, output_path=args.output, verbose=args.verbose)

    return 1 if total_issues > 0 or has_errors or has_degraded_analyses else 0


__all__ = ["cmd_scan_async"]
