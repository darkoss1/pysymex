# pysymex: Python Symbolic Execution & Formal Verification
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
import inspect
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from pysymex.scanner.types import ScanResult

_Namespace = argparse.Namespace
from pysymex.cli.output import emit_cli_output, print_cli_error
from pysymex.pathing import normalize_input_path


def _typed_scan_results(results: Sequence[object]) -> list[ScanResult]:
    from pysymex.scanner.types import ScanResult as _ScanResult

    return [result for result in results if isinstance(result, _ScanResult)]


@runtime_checkable
class _IndexableObjectSequence(Protocol):
    """Protocol for indexable sequences of opaque objects."""

    def __len__(self) -> int:
        """Return sequence length."""
        ...

    def __getitem__(self, index: int) -> object:
        """Return sequence item by index."""
        ...


def _call_with_supported_kwargs(
    func: Callable[..., object],
    *args: object,
    **kwargs: object,
) -> object:
    """Call *func* with only keyword args accepted by its runtime signature."""
    signature = inspect.signature(func)
    if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in signature.parameters.values()):
        return func(*args, **kwargs)
    filtered = {k: v for k, v in kwargs.items() if k in signature.parameters}
    return func(*args, **filtered)


def _stop_stats_if_requested(args: _Namespace) -> None:
    """Stop stats before final report emission to avoid post-report metric lines."""
    if not getattr(args, "stats", False):
        return
    if getattr(args, "_stats_stopped", False):
        return
    from pysymex.stats import stop

    stop()
    setattr(args, "_stats_stopped", True)


def cmd_scan(args: _Namespace) -> int:
    """Execute the ``scan`` sub-command.

    Dispatches to the appropriate scan handler based on ``args.mode``
    (symbolic, static, or pipeline).

    Args:
        args: Parsed CLI namespace.

    Returns:
        ``1`` if issues were found, ``0`` otherwise.
    """

    path = normalize_input_path(str(args.path))
    if not path.exists():
        print_cli_error(f"Path not found: {path}")
        return 1

    if args.verbose:
        print(f"[SCAN] Scanning: {path} (mode: {args.mode})")

    stop_stats: Callable[[], None] | None = None
    if getattr(args, "stats", False):
        from pysymex.stats import enable_console_sink, start, stop

        enable_console_sink()
        stop_stats = stop
        start()

    start_time = time.time()

    try:
        if args.mode == "static":
            return _handle_static_scan(args, start_time)
        elif args.mode == "pipeline":
            return _handle_pipeline_scan(args, start_time)

        return _handle_symbolic_scan(args, path, start_time)
    finally:
        if stop_stats is not None and not getattr(args, "_stats_stopped", False):
            stop_stats()


async def cmd_scan_async(args: _Namespace) -> int:
    """Execute scan command using async TaskGroup-based scanner.

    Called when the user passes ``--async`` to the CLI.  Uses
    :func:`pysymex.scanner.async_scanner.scan_directory_async` for
    structured-concurrency scanning with graceful shutdown support.
    """
    from pysymex.core.shutdown import install_signal_handlers

    path = normalize_input_path(str(args.path))
    if not path.exists():
        print_cli_error(f"Path not found: {path}")
        return 1

    if args.verbose:
        print(f"[SCAN] Async scanning: {path} (mode: {args.mode})")

    import asyncio

    loop = asyncio.get_running_loop()
    install_signal_handlers(loop)

    start_time = time.time()

    if args.mode in ("static", "pipeline"):
        import asyncio as _aio

        if args.mode == "static":
            result = await _aio.to_thread(_handle_static_scan, args, start_time)
        else:
            result = await _aio.to_thread(_handle_pipeline_scan, args, start_time)
        return result

    return await _handle_symbolic_scan_async(args, path, start_time)


async def _handle_symbolic_scan_async(
    args: _Namespace,
    path: Path,
    start_time: float,
) -> int:
    """Handle symbolic scan using async TaskGroup scanner."""
    import asyncio

    from pysymex.cli.reporter import ConsoleScanReporter
    from pysymex.scanner.async_scanner import scan_directory_async

    reporter = ConsoleScanReporter() if args.verbose else None
    deterministic_mode = args.deterministic or path.is_file()

    if path.is_file():
        from pysymex.scanner.core import scan_file

        result = await asyncio.to_thread(
            scan_file,
            path,
            verbose=args.verbose,
            max_paths=args.max_paths,
            timeout=args.timeout,
            auto_tune=args.auto,
            reporter=reporter,
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
        results = await scan_directory_async(
            args.path,
            pattern=pattern,
            verbose=args.verbose,
            max_paths=args.max_paths,
            timeout=args.timeout,
            max_concurrency=args.workers if args.workers > 0 else None,
            auto_tune=args.auto,
            trace_enabled=args.trace,
            trace_output_dir=args.trace_output_dir,
            trace_verbosity=args.trace_verbosity,
        )

    if not results and path.is_file():
        _stop_stats_if_requested(args)
        print_cli_error(f"No valid scan results were produced for: {path}")
        return 1

    total_issues = sum(len(r.issues) for r in results)
    duration = time.time() - start_time

    from pysymex.cli.formatters import get_formatter

    formatter = get_formatter(args.format)
    show_stats = getattr(args, "stats", False)
    output = formatter.format_symbolic(results, total_issues, duration, args.reproduce, show_stats)

    _stop_stats_if_requested(args)
    emit_cli_output(output, output_path=args.output, verbose=args.verbose)

    return 1 if total_issues > 0 else 0


def _handle_static_scan(args: _Namespace, start_time: float) -> int:
    """Handle the *static* analysis mode.

    Args:
        args: Parsed CLI namespace.
        start_time: Epoch timestamp from scan start.

    Returns:
        ``1`` if issues were found, ``0`` otherwise.
    """
    from pysymex.api import scan_static

    issues = scan_static(
        normalize_input_path(str(args.path)),
        recursive=args.recursive,
        verbose=args.verbose,
        min_confidence=0.7,
        show_suppressed=False,
    )

    show_suppressed = getattr(args, "show_suppressed", False)
    if not show_suppressed:
        active_issues = [i for i in issues if not i.is_suppressed()]
    else:
        active_issues = list(issues)
    total_issues = len(active_issues)
    suppressed_count = len(issues) - len(active_issues)
    duration = time.time() - start_time

    from pysymex.cli.formatters import get_formatter

    formatter = get_formatter(args.format)
    output = formatter.format_static(active_issues, total_issues, suppressed_count, duration)

    _stop_stats_if_requested(args)

    if args.format == "sarif":
        emit_cli_output(output, output_path=args.output, verbose=args.verbose)
        return 0

    emit_cli_output(output, output_path=args.output, verbose=args.verbose)
    return 1 if total_issues > 0 else 0


def _handle_pipeline_scan(args: _Namespace, start_time: float) -> int:
    """Handle the full *pipeline* analysis mode.

    Combines static and symbolic analysis into a single pipeline.

    Args:
        args: Parsed CLI namespace.
        start_time: Epoch timestamp from scan start.

    Returns:
        ``1`` if issues were found, ``0`` otherwise.
    """
    from pysymex.api import scan_pipeline

    results = scan_pipeline(
        normalize_input_path(str(args.path)),
        recursive=args.recursive,
    )

    all_issues: list[tuple[str, Any]] = []
    for file_path, result in results.items():
        for issue in result.issues:
            all_issues.append((file_path, issue))

    total_issues = len(all_issues)
    duration = time.time() - start_time

    from pysymex.cli.formatters import get_formatter

    formatter = get_formatter(args.format)
    output = formatter.format_pipeline(results, all_issues, total_issues, duration)

    _stop_stats_if_requested(args)
    emit_cli_output(output, output_path=args.output, verbose=args.verbose)
    return 1 if total_issues > 0 else 0


def _handle_symbolic_scan(args: _Namespace, path: Path, start_time: float) -> int:
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
    if getattr(args, "visualize", False):
        from pysymex.reporting.realtime import run_realtime_scan

        results = run_realtime_scan(
            path, recursive=args.recursive, max_paths=args.max_paths, timeout=args.timeout
        )
    else:
        from pysymex.cli.reporter import ConsoleScanReporter
        from pysymex.scanner.core import scan_directory, scan_file

        show_stats = getattr(args, "stats", False)
        reporter = ConsoleScanReporter(show_stats=show_stats) if args.verbose else None
        deterministic_mode = args.deterministic or path.is_file()

        results: list["ScanResult"]
        if path.is_file():
            raw_result = _call_with_supported_kwargs(
                scan_file,
                path,
                verbose=args.verbose,
                max_paths=args.max_paths,
                timeout=args.timeout,
                auto_tune=args.auto,
                reporter=reporter,
                use_sandbox=args.sandbox,
                use_chtd=args.use_chtd,
                use_h_acceleration=args.use_h_acceleration,
                deterministic_mode=deterministic_mode,
                random_seed=args.seed,
                no_cache=getattr(args, "no_cache", False),
                max_iterations=getattr(args, "max_iterations", 0),
                trace_enabled=args.trace,
                trace_output_dir=args.trace_output_dir,
                trace_verbosity=args.trace_verbosity,
            )
            results = _typed_scan_results([raw_result])
        else:
            from pysymex.scanner.types import ScanResult as _ScanResult

            pattern = "**/*.py" if args.recursive else "*.py"
            raw_results = _call_with_supported_kwargs(
                scan_directory,
                args.path,
                pattern=pattern,
                verbose=args.verbose,
                max_paths=args.max_paths,
                timeout=args.timeout,
                workers=args.workers,
                auto_tune=args.auto,
                reporter=reporter,
                use_sandbox=args.sandbox,
                use_chtd=args.use_chtd,
                use_h_acceleration=args.use_h_acceleration,
                deterministic_mode=args.deterministic,
                random_seed=args.seed,
                no_cache=getattr(args, "no_cache", False),
                max_iterations=getattr(args, "max_iterations", 0),
                trace_enabled=args.trace,
                trace_output_dir=args.trace_output_dir,
                trace_verbosity=args.trace_verbosity,
            )
            if isinstance(raw_results, _IndexableObjectSequence):
                results = []
                for index in range(len(raw_results)):
                    item = raw_results[index]
                    if isinstance(item, _ScanResult):
                        results.append(item)
            else:
                results = []

    if not results and path.is_file():
        _stop_stats_if_requested(args)
        print_cli_error(f"No valid scan results were produced for: {path}")
        return 1

    total_issues = sum(len(r.issues) for r in results)
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

        _stop_stats_if_requested(args)
        emit_cli_output(output, output_path=args.output, verbose=args.verbose)
    except Exception as e:
        _stop_stats_if_requested(args)
        print_cli_error(f"Internal error during report generation: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1

    return 1 if total_issues > 0 else 0
