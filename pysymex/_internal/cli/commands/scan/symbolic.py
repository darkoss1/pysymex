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

from pysymex._internal.cli.commands.scan.shared import (
    IndexableObjectSequence,
    call_with_supported_kwargs,
    publish_scan_stats_if_requested,
    stop_stats_if_requested,
    typed_scan_results,
)
from pysymex._internal.cli.output import CliOutput
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from pysymex._internal.profiling.model import ScanProfileReport
    from pysymex._internal.profiling.session import ProfileMode, ProfileRun, ScanProfilerSession
    from pysymex._internal.scanner.types import ScanResult

_Namespace = argparse.Namespace
logger = get_logger(__name__)
emit_cli_output = CliOutput.emit


def handle_symbolic_scan(args: _Namespace, path: Path, start_time: float) -> int:
    """Handle the default *symbolic* analysis mode.

    Delegates to :func:`pysymex._internal.scanner.scan_file` or
    :func:`pysymex._internal.scanner.scan_directory` depending on whether
    *path* is a file or directory.

    Args:
        args: Parsed CLI namespace.
        path: Target file or directory.
        start_time: Epoch timestamp from scan start.

    Returns:
        ``1`` if issues were found, ``0`` otherwise.

    """
    use_sandbox = not getattr(args, "no_sandbox", False)
    max_depth = getattr(args, "max_depth", None)

    from pysymex._internal.cli.reporter import ConsoleScanReporter
    from pysymex._internal.scanner.directory.scan import scan_directory
    from pysymex._internal.scanner.file import scan_file
    from pysymex._internal.scanner.types import ScanResult

    if getattr(args, "visualize", False):
        import webbrowser

        from pysymex._internal.reporting.realtime.scan import run_realtime_scan
    else:
        webbrowser = None
        run_realtime_scan = None

    scan_profile_session = _start_scan_profile_if_requested(args, path)
    profile_run: ProfileRun | None = None
    results: list[ScanResult] = []
    try:
        if getattr(args, "visualize", False):
            assert run_realtime_scan is not None
            assert webbrowser is not None
            logger.verbose("Symbolic scan starting realtime mode path=%s", path)
            results = run_realtime_scan(
                path,
                max_paths=args.max_paths,
                max_depth=max_depth,
                timeout=args.timeout,
                auto_tune=True,
                use_sandbox=use_sandbox,
                no_cache=getattr(args, "no_cache", False),
                max_iterations=getattr(args, "max_iterations", None),
                trace_enabled=args.trace,
                trace_output_dir=args.trace_output_dir,
                trace_verbosity=args.trace_verbosity,
                detect_overflow=getattr(args, "detect_overflow", False),
                open_url=webbrowser.open,
                message_sink=CliOutput.safe_print,
            )
        else:
            show_stats = getattr(args, "stats", False)
            reporter = ConsoleScanReporter(show_stats=show_stats) if args.verbose else None
            logger.verbose("Symbolic scan started path=%s", path)

            if path.is_file():
                raw_result = call_with_supported_kwargs(
                    scan_file,
                    path,
                    verbose=args.verbose,
                    max_paths=args.max_paths,
                    max_depth=max_depth,
                    timeout=args.timeout,
                    auto_tune=True,
                    reporter=reporter,
                    use_sandbox=use_sandbox,
                    no_cache=getattr(args, "no_cache", False),
                    max_iterations=getattr(args, "max_iterations", None),
                    trace_enabled=args.trace,
                    trace_output_dir=args.trace_output_dir,
                    trace_verbosity=args.trace_verbosity,
                    detect_overflow=getattr(args, "detect_overflow", False),
                    function_filter=getattr(args, "function", None),
                )
                results = typed_scan_results([raw_result])
            else:
                pattern = getattr(args, "_scan_glob_pattern", None)
                if not isinstance(pattern, str):
                    pattern = "**/*.py"
                raw_results = call_with_supported_kwargs(
                    scan_directory,
                    path,
                    pattern=pattern,
                    verbose=args.verbose,
                    max_paths=args.max_paths,
                    max_depth=max_depth,
                    timeout=args.timeout,
                    workers=args.workers,
                    auto_tune=True,
                    reporter=reporter,
                    use_sandbox=use_sandbox,
                    no_cache=getattr(args, "no_cache", False),
                    max_iterations=getattr(args, "max_iterations", None),
                    trace_enabled=args.trace,
                    trace_output_dir=args.trace_output_dir,
                    trace_verbosity=args.trace_verbosity,
                    detect_overflow=getattr(args, "detect_overflow", False),
                    function_filter=getattr(args, "function", None),
                )
                if isinstance(raw_results, IndexableObjectSequence):
                    results = []
                    for index in range(len(raw_results)):
                        item = raw_results[index]
                        if isinstance(item, ScanResult):
                            results.append(item)
                else:
                    results = []
    finally:
        profile_run = _finish_scan_profile(scan_profile_session)

    if not results and path.is_file():
        logger.warning("Symbolic scan produced no result for file %s", path)
        stop_stats_if_requested(args)
        CliOutput.error(f"No valid scan results were produced for: {path}")
        return 1

    total_issues = sum(len(r.issues) for r in results)
    has_errors = any(r.error is not None for r in results)
    duration = time.time() - start_time

    try:
        if args.format in {"json", "sarif"}:
            from pysymex._internal.cli.formatters.registry import get_formatter

            formatter = get_formatter(args.format)
            output = formatter.format_symbolic(
                results,
                total_issues,
                duration,
                args.reproduce,
                getattr(args, "stats", False),
            )
        else:
            from pysymex._internal.cli.formatters.registry import get_formatter

            formatter = get_formatter(args.format)
            show_stats = getattr(args, "stats", False)
            output = formatter.format_symbolic(
                results,
                total_issues,
                duration,
                args.reproduce,
                show_stats,
            )

        publish_scan_stats_if_requested(args, results)
        stop_stats_if_requested(args)
        profile_report = _build_scan_profile_if_requested(
            args,
            results,
            profile_run,
            duration,
            path,
        )
        emit_cli_output(output, output_path=args.output, verbose=args.verbose)
        if profile_report is not None:
            from pysymex._internal.profiling.rendering import ScanProfileReports

            CliOutput.safe_print(ScanProfileReports.format(profile_report))
    except Exception as e:
        logger.warning("Symbolic scan report generation failed for %s", path, exc_info=True)
        stop_stats_if_requested(args)
        CliOutput.error(f"Internal error during report generation: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1

    return 1 if total_issues > 0 or has_errors else 0


def _start_scan_profile_if_requested(
    args: _Namespace,
    path: Path,
) -> ScanProfilerSession | None:
    """Start scan profiling when ``--profile`` is active."""
    if not getattr(args, "profile", False):
        return None
    from pysymex._internal.profiling.session import ScanProfilerSession

    return ScanProfilerSession.start(
        output_dir=getattr(args, "profile_output_dir", ".pysymex/profiles"),
        project_root=Path.cwd(),
        target_path=path,
        mode=_profile_mode(args),
        sample_interval_seconds=_profile_sample_interval_seconds(args),
    )


def _finish_scan_profile(session: ScanProfilerSession | None) -> ProfileRun | None:
    """Finish an active scan profiling session."""
    if session is None:
        return None
    return session.finish()


def _build_scan_profile_if_requested(
    args: _Namespace,
    results: list[ScanResult],
    profile_run: ProfileRun | None,
    wall_time_seconds: float,
    target_path: Path,
) -> ScanProfileReport | None:
    """Build, optionally compare, and persist one consistent profile report."""
    if not getattr(args, "profile", False):
        return None
    from pysymex._internal.profiling.comparison import compare_profile_report
    from pysymex._internal.profiling.model import ProfileConfiguration, ScanProfileReport
    from pysymex._internal.profiling.rendering import ScanProfileReports

    profile_output_dir = getattr(args, "profile_output_dir", ".pysymex/profiles")
    report = ScanProfileReport.from_scan_results(
        results,
        trace_output_dir=str(args.trace_output_dir),
        profile_run=profile_run,
        stats_metrics=_scan_stats_metrics(),
        wall_time_seconds=wall_time_seconds,
        configuration=ProfileConfiguration(
            target_path=str(target_path),
            workers=_namespace_int(args, "workers"),
            max_paths=_namespace_optional_int(args, "max_paths"),
            max_depth=_namespace_optional_int(args, "max_depth"),
            timeout_seconds=_namespace_optional_float(args, "timeout"),
            max_iterations=_namespace_optional_int(args, "max_iterations"),
            cache_enabled=not getattr(args, "no_cache", False),
            sandbox_enabled=not getattr(args, "no_sandbox", False),
            trace_verbosity=str(getattr(args, "trace_verbosity", "delta_only")),
            profile_mode=str(getattr(args, "profile_mode", "sample")),
            profile_sample_interval_ms=_profile_sample_interval_ms(args),
            auto_tune=True,
            detect_overflow=bool(getattr(args, "detect_overflow", False)),
            scan_pattern=_namespace_optional_str(args, "_scan_glob_pattern"),
        ),
    )
    baseline_path = getattr(args, "profile_baseline", None)
    if isinstance(baseline_path, str) and baseline_path:
        report = report.with_comparison(compare_profile_report(report, baseline_path))
    summary_path = ScanProfileReports.write_summary(report, profile_output_dir)
    return report.with_summary_path(summary_path)


def _profile_mode(args: _Namespace) -> ProfileMode:
    """Return the validated profiler mode from the CLI namespace."""
    from pysymex._internal.profiling.session import DEFAULT_PROFILE_MODE, PROFILE_MODE_CHOICES

    value = getattr(args, "profile_mode", DEFAULT_PROFILE_MODE)
    if isinstance(value, str) and value in PROFILE_MODE_CHOICES:
        return value
    return DEFAULT_PROFILE_MODE


def _profile_sample_interval_seconds(args: _Namespace) -> float:
    """Return the sampling interval in seconds for the profile backend."""
    return _profile_sample_interval_ms(args) / 1000.0


def _profile_sample_interval_ms(args: _Namespace) -> float:
    """Return a non-negative sampling interval in milliseconds from the CLI namespace."""
    value = getattr(args, "profile_sample_interval_ms", 5.0)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 5.0
    return max(0.0, float(value))


def _namespace_int(args: _Namespace, name: str) -> int:
    """Return a non-negative integer from a validated CLI namespace."""
    value = getattr(args, name, 0)
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return max(0, value)


def _namespace_optional_int(args: _Namespace, name: str) -> int | None:
    """Return an optional positive integer from a validated CLI namespace."""
    value = getattr(args, name, None)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if value > 0 else None


def _namespace_optional_float(args: _Namespace, name: str) -> float | None:
    """Return an optional positive float from a validated CLI namespace."""
    value = getattr(args, name, None)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    numeric = float(value)
    return numeric if numeric > 0 else None


def _namespace_optional_str(args: _Namespace, name: str) -> str | None:
    """Return an optional string from a CLI namespace."""
    value = getattr(args, name, None)
    return value if isinstance(value, str) else None


def _scan_stats_metrics() -> dict[str, object]:
    """Return the current stats registry metrics without starting stats collection."""
    from pysymex._internal.stats.runtime import registry

    return dict(registry.global_metrics)
