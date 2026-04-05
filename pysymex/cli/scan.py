# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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
import json
import sys
import time
from collections import defaultdict
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from pysymex.analysis.detectors import Issue
    from pysymex.scanner.types import ScanResult

_Namespace = argparse.Namespace

from pysymex import __version__


def _typed_scan_results(results: Sequence[object]) -> list[ScanResult]:
    from pysymex.scanner.types import ScanResult as _ScanResult

    return [result for result in results if isinstance(result, _ScanResult)]


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


def cmd_scan(args: _Namespace) -> int:
    """Execute the ``scan`` sub-command.

    Dispatches to the appropriate scan handler based on ``args.mode``
    (symbolic, static, or pipeline).

    Args:
        args: Parsed CLI namespace.

    Returns:
        ``1`` if issues were found, ``0`` otherwise.
    """

    path = Path(str(args.path))
    if not path.exists():
        print(f"\u274c Error: Path not found: {path}", file=sys.stderr)
        return 1

    if args.verbose:
        print(f"\U0001f50d Scanning: {path} (mode: {args.mode})")

    start_time = time.time()

    if args.mode == "static":
        return _handle_static_scan(args, start_time)
    elif args.mode == "pipeline":
        return _handle_pipeline_scan(args, start_time)

    return _handle_symbolic_scan(args, path, start_time)


async def cmd_scan_async(args: _Namespace) -> int:
    """Execute scan command using async TaskGroup-based scanner.

    Called when the user passes ``--async`` to the CLI.  Uses
    :func:`pysymex.scanner.async_scanner.scan_directory_async` for
    structured-concurrency scanning with graceful shutdown support.
    """
    from pysymex.core.shutdown import install_signal_handlers

    path = Path(str(args.path))
    if not path.exists():
        print(f"\u274c Error: Path not found: {path}", file=sys.stderr)
        return 1

    if args.verbose:
        print(f"\U0001f50d Async scanning: {path} (mode: {args.mode})")

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

    from pysymex.cli.scan_reporter import ConsoleScanReporter
    from pysymex.scanner.async_scanner import scan_directory_async

    reporter = ConsoleScanReporter() if args.verbose else None

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

    total_issues = sum(len(r.issues) for r in results)
    duration = time.time() - start_time

    if args.format == "json":
        output_data = {
            "pysymex_version": __version__,
            "mode": "symbolic-async",
            "files_scanned": len(results),
            "total_issues": total_issues,
            "results": [r.to_dict() for r in results],
            "duration": duration,
        }
        output = json.dumps(output_data, indent=2, default=str)
    elif args.format == "sarif":
        output = get_symbolic_sarif(results)
    else:
        output = format_symbolic_text_report(results, total_issues, args.reproduce)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        if args.verbose:
            print(f"\U0001f4c4 Report saved to: {args.output}")
    else:
        print(output)

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
        Path(args.path),
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

    if args.format == "json":
        output_data = {
            "pysymex_version": __version__,
            "mode": "static",
            "total_issues": total_issues,
            "suppressed_issues": suppressed_count,
            "issues": [i.to_dict() for i in active_issues],
            "duration": duration,
        }
        output = json.dumps(output_data, indent=2, default=str)
    elif args.format == "sarif":
        _print_static_sarif(active_issues)
        return 0
    else:
        output = format_static_text_report(active_issues, total_issues, suppressed_count)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        if args.verbose:
            print(f"\U0001f4c4 Report saved to: {args.output}")
    else:
        print(output)
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
        Path(args.path),
        recursive=args.recursive,
    )

    all_issues: list[tuple[object, object]] = []
    for file_path, result in results.items():
        for issue in result.issues:
            all_issues.append((file_path, issue))

    total_issues = len(all_issues)
    duration = time.time() - start_time

    if args.format == "json":
        import json as json_mod

        output_data = {
            "pysymex_version": __version__,
            "mode": "pipeline",
            "files_scanned": len(results),
            "total_issues": total_issues,
            "results": {
                fp: {
                    "issues": len(r.issues),
                    "taint_violations": len(r.taint_violations),
                    "analysis_time": r.analysis_time,
                    "functions_analyzed": r.functions_analyzed,
                    "lines_of_code": r.lines_of_code,
                }
                for fp, r in results.items()
            },
            "duration": duration,
        }
        output = json_mod.dumps(output_data, indent=2, default=str)
    else:
        lines = [
            "",
            "+" + "=" * 58 + "+",
            "|" + "  PySyMex Pipeline Scan".center(58) + "|",
            "+" + "=" * 58 + "+",
            "",
            f"  Files: {len(results)}",
            f"  Issues: {total_issues}",
            "",
        ]
        if total_issues == 0:
            lines.append("  No issues found!")
        else:
            for file_path, issue in all_issues:
                sev = getattr(issue, "severity", None)
                sev_name = sev.name if sev is not None and hasattr(sev, "name") else str(sev)
                lines.append(
                    f"  [{sev_name}] {file_path}:{getattr(issue, 'line', '?')} "
                    f"- {getattr(issue, 'message', '')}"
                )
        lines.extend(["", "-" * 60])
        output = "\n".join(lines)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        if args.verbose:
            print(f"Report saved to: {args.output}")
    else:
        print(output)
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
        from pysymex.cli.scan_reporter import ConsoleScanReporter
        from pysymex.scanner.core import scan_directory, scan_file

        reporter = ConsoleScanReporter() if args.verbose else None

        if path.is_file():
            results = [
                cast(
                    "ScanResult",
                    _call_with_supported_kwargs(
                        scan_file,
                        path,
                        verbose=args.verbose,
                        max_paths=args.max_paths,
                        timeout=args.timeout,
                        auto_tune=args.auto,
                        reporter=reporter,
                        use_sandbox=args.sandbox,
                        use_chtd=True,
                        use_h_acceleration=True,
                        deterministic_mode=args.deterministic,
                        random_seed=args.seed,
                        trace_enabled=args.trace,
                        trace_output_dir=args.trace_output_dir,
                        trace_verbosity=args.trace_verbosity,
                    ),
                )
            ]
        else:
            pattern = "**/*.py" if args.recursive else "*.py"
            results = cast(
                "list[ScanResult]",
                _call_with_supported_kwargs(
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
                    use_chtd=True,
                    use_h_acceleration=True,
                    deterministic_mode=args.deterministic,
                    random_seed=args.seed,
                    trace_enabled=args.trace,
                    trace_output_dir=args.trace_output_dir,
                    trace_verbosity=args.trace_verbosity,
                ),
            )

    total_issues = sum(len(r.issues) for r in results)
    duration = time.time() - start_time

    if args.format == "json":
        output_data = {
            "pysymex_version": __version__,
            "mode": "symbolic",
            "files_scanned": len(results),
            "total_issues": total_issues,
            "results": [r.to_dict() for r in results],
            "duration": duration,
        }
        output = json.dumps(output_data, indent=2, default=str)
    elif args.format == "sarif":
        output = get_symbolic_sarif(results)
    else:
        output = format_symbolic_text_report(results, total_issues, args.reproduce)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        if args.verbose:
            print(f"\U0001f4c4 Report saved to: {args.output}")
    else:
        print(output)
    return 1 if total_issues > 0 else 0


def _issue_line_for_sort(issue: object) -> int:
    line_val = getattr(issue, "line", 0)
    return line_val if isinstance(line_val, int) else 0


def format_static_text_report(issues: Sequence[object], total: int, suppressed: int = 0) -> str:
    """Format a human-readable text report for a static scan.

    Args:
        issues: List of issue objects with ``kind``, ``line``,
            ``message``, and ``severity`` attributes.
        total: Total number of active (non-suppressed) issues.
        suppressed: Number of suppressed issues.

    Returns:
        Multi-line string suitable for terminal output.
    """
    lines = [
        "",
        "\u2554" + "\u2550" * 58 + "\u2557",
        "\u2551" + "  \U0001f52e PySyMex Static Scan".center(58) + "\u2551",
        "\u255a" + "\u2550" * 58 + "\u255d",
        "",
    ]
    lines.append(f"  \U0001f41b Issues:  {total}")
    if suppressed > 0:
        lines.append(f"  \U0001f507 Suppressed:  {suppressed} (likely false positives)")
    lines.append("")

    if total == 0:
        lines.append("  \u2705 No issues found!")
    else:
        by_file: defaultdict[str, list[object]] = defaultdict(list)
        for issue in issues:
            by_file[getattr(issue, "file", "unknown")].append(issue)

        for fpath, file_issues in by_file.items():
            lines.append(f"  \u2500\u2500\u2500 {fpath} \u2500\u2500\u2500")
            for issue in sorted(file_issues, key=_issue_line_for_sort):
                icon = {"error": "\U0001f534", "warning": "\U0001f7e0"}.get(
                    getattr(issue, "severity", "warning"), "\U0001f7e1"
                )
                kind = getattr(issue, "kind", "UNKNOWN")
                line = getattr(issue, "line", "?")
                message = getattr(issue, "message", "")
                lines.append(f"    {icon} [{kind}] Line {line}: {message}")
                suggestion = getattr(issue, "suggestion", None)
                if isinstance(suggestion, str) and suggestion:
                    lines.append(f"       \U0001f4a1 {suggestion}")
    lines.extend(["", "\u2500" * 60])
    return "\n".join(lines)


def format_symbolic_text_report(results: Sequence[object], total: int, reproduce: bool) -> str:
    """Format a human-readable text report for a symbolic scan.

    Args:
        results: List of :class:`~pysymex.scanner.types.ScanResult` objects.
        total: Total number of issues across all results.
        reproduce: Whether to append reproduction-script information.

    Returns:
        Multi-line string suitable for terminal output.
    """
    lines = [
        "",
        "\u2554" + "\u2550" * 58 + "\u2557",
        "\u2551" + "  \U0001f52e PySyMex Symbolic Scan".center(58) + "\u2551",
        "\u255a" + "\u2550" * 58 + "\u255d",
        "",
    ]
    lines.append(f"  \U0001f4c1 Scanned: {len(results)} file(s)")
    lines.append(f"  \U0001f41b Issues:  {total}")
    lines.append("")

    if total == 0:
        lines.append("  \u2705 No issues found!")
    else:
        for scan_result in _typed_scan_results(results):
            if not scan_result.issues:
                continue
            lines.append(f"  \u2500\u2500\u2500 {scan_result.file_path} \u2500\u2500\u2500")
            for issue in scan_result.issues:
                kind = issue.get("kind", "UNKNOWN")
                icon = (
                    "\U0001f534"
                    if kind in ("DIVISION_BY_ZERO", "ASSERTION_ERROR")
                    else "\U0001f7e0"
                    if kind in ("INDEX_ERROR", "KEY_ERROR")
                    else "\U0001f7e1"
                )
                lines.append(
                    f"    {icon} [{kind}] Line {issue.get('line', '?')}: {issue.get('message', '')}"
                )
                ce = issue.get("counterexample")
                if isinstance(ce, dict):
                    lines.append(
                        f"       \u21b3 Trigger: {', '.join(f'{k}={v}' for k, v in ce.items())}"
                    )
            if reproduce:
                _add_reproduction_info(lines, scan_result.issues, scan_result.file_path)
    lines.append("\u2500" * 60)
    return "\n".join(lines)


def _add_reproduction_info(
    lines: list[str], issues: Sequence[dict[str, object]], file_path: object
) -> None:
    """Append reproduction-script paths to *lines*.

    Args:
        lines: Accumulator list of report lines (mutated in-place).
        issues: Issue dicts that may contain ``counterexample`` data.
        file_path: Source file the issues belong to.
    """
    from pysymex.reporting.reproduction import ReproductionGenerator

    gen = ReproductionGenerator()
    lines.extend(["", "    [!] Reproduction Scripts:"])
    for issue in issues:
        if issue.get("counterexample"):
            kind_obj = issue.get("kind", "UNKNOWN")
            kind_name = kind_obj if isinstance(kind_obj, str) else "UNKNOWN"
            message_obj = issue.get("message", "")
            issue_message = message_obj if isinstance(message_obj, str) else str(message_obj)
            class_name_obj = issue.get("class_name")
            class_name = class_name_obj if isinstance(class_name_obj, str) else None
            counterexample_obj = issue.get("counterexample")
            counterexample = counterexample_obj if isinstance(counterexample_obj, dict) else None

            class _IssueKind:
                def __init__(self, name: str) -> None:
                    self.name = name

            class IssueObj:
                """Data object representing a detected issue for reproduction."""

                def __init__(self, data: dict[str, object]) -> None:
                    _ = data
                    self.counterexample = counterexample
                    self.kind = _IssueKind(kind_name)
                    self.message = issue_message
                    self.class_name = class_name

            function_name_obj = issue.get("function_name", "unknown")
            function_name = function_name_obj if isinstance(function_name_obj, str) else "unknown"
            script = gen.generate(
                cast("Issue", IssueObj(issue)),
                function_name,
                str(file_path),
                class_name=class_name,
            )
            if script:
                lines.append(f"       + {script}")


def get_symbolic_sarif(results: Sequence[object]) -> str:
    """Generate a SARIF 2.1.0 JSON string from symbolic scan results.

    Args:
        results: List of :class:`~pysymex.scanner.types.ScanResult` objects.

    Returns:
        SARIF JSON string.
    """
    from pysymex.reporting.sarif import SARIFGenerator

    generator = SARIFGenerator()
    all_issues: list[dict[str, object]] = []
    all_files: list[str] = []
    for scan_result in _typed_scan_results(results):
        all_files.append(str(scan_result.file_path))
        for issue in scan_result.issues:
            si = issue.copy()
            si["type"] = issue.get("kind", "UNKNOWN")
            si["file"] = str(scan_result.file_path)
            all_issues.append(si)
    return generator.generate(issues=all_issues, analyzed_files=all_files).to_json()


def _print_static_sarif(issues: Sequence[object]) -> None:
    """Print static-analysis results directly to stdout in SARIF format.

    Args:
        issues: Issue objects with a ``to_dict()`` method.
    """
    from pysymex.reporting.sarif import generate_sarif

    issue_dicts: list[dict[str, object]] = []
    for issue in issues:
        to_dict = getattr(issue, "to_dict", None)
        if callable(to_dict):
            result = to_dict()
            if isinstance(result, dict):
                issue_dicts.append(result)
    sarif_log = generate_sarif(issues=issue_dicts)
    print(sarif_log.to_json())
