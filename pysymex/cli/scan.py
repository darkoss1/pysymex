"""Scan-related CLI commands and formatters for pysymex."""

from __future__ import annotations


import json

import sys

import time

from collections import defaultdict

from pathlib import Path

from typing import Any


import argparse

_Namespace = argparse.Namespace


try:
    from importlib.metadata import version as pkg_version

    __version__ = pkg_version("pysymex")

except Exception:
    __version__ = "0.1.0a0"


def cmd_scan(args: _Namespace) -> int:
    """Execute scan command."""

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


def _handle_static_scan(args: _Namespace, start_time: float) -> int:
    """Handle static analysis mode."""

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
    """Handle full analysis pipeline mode."""

    from pysymex.api import scan_pipeline

    results = scan_pipeline(
        Path(args.path),
        recursive=args.recursive,
    )

    all_issues: list[tuple[Any, Any]] = []

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
    """Handle symbolic analysis mode."""

    if getattr(args, "visualize", False):
        from pysymex.reporting.realtime import run_realtime_scan

        results = run_realtime_scan(
            path, recursive=args.recursive, max_paths=args.max_paths, timeout=args.timeout
        )

    else:
        from pysymex.scanner import scan_directory, scan_file

        if path.is_file():
            results = [
                scan_file(
                    path,
                    verbose=args.verbose,
                    max_paths=args.max_paths,
                    timeout=args.timeout,
                    auto_tune=args.auto,
                )
            ]

        else:
            pattern = "**/*.py" if args.recursive else "*.py"

            results = scan_directory(
                args.path,
                pattern=pattern,
                verbose=args.verbose,
                max_paths=args.max_paths,
                timeout=args.timeout,
                workers=args.workers,
                auto_tune=args.auto,
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


def format_static_text_report(issues: list[Any], total: int, suppressed: int = 0) -> str:
    """Format text report for static scan."""

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
        by_file: defaultdict[str, list[Any]] = defaultdict(list)

        for issue in issues:
            by_file[getattr(issue, "file", "unknown")].append(issue)

        for fpath, file_issues in by_file.items():
            lines.append(f"  \u2500\u2500\u2500 {fpath} \u2500\u2500\u2500")

            for issue in sorted(file_issues, key=lambda x: x.line):
                icon = {"error": "\U0001f534", "warning": "\U0001f7e0"}.get(
                    getattr(issue, "severity", "warning"), "\U0001f7e1"
                )

                lines.append(f"    {icon} [{issue.kind}] Line {issue.line}: {issue.message}")

                if getattr(issue, "suggestion", None):
                    lines.append(f"       \U0001f4a1 {issue.suggestion}")

    lines.extend(["", "\u2500" * 60])

    return "\n".join(lines)


def format_symbolic_text_report(results: list[Any], total: int, reproduce: bool) -> str:
    """Format text report for symbolic scan."""

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
        for result in results:
            if not result.issues:
                continue

            lines.append(f"  \u2500\u2500\u2500 {result.file_path} \u2500\u2500\u2500")

            for issue in result.issues:
                kind = issue.get("kind", "UNKNOWN")

                icon = (
                    "\U0001f534"
                    if kind in ("DIVISION_BY_ZERO", "ASSERTION_ERROR")
                    else "\U0001f7e0" if kind in ("INDEX_ERROR", "KEY_ERROR") else "\U0001f7e1"
                )

                lines.append(
                    f"    {icon} [{kind}] Line {issue.get('line_number', '?')}: {issue.get('message', '')}"
                )

                ce = issue.get("counterexample")

                if ce:
                    lines.append(
                        f"       \u21b3 Trigger: {', '.join(f'{k}={v}' for k, v in ce.items())}"
                    )

            if reproduce:
                _add_reproduction_info(lines, result.issues, result.file_path)

    lines.append("\u2500" * 60)

    return "\n".join(lines)


def _add_reproduction_info(lines: list[str], issues: list[dict[str, Any]], file_path: Any) -> None:
    """Add reproduction links to lines."""

    from pysymex.reporting.reproduction import ReproductionGenerator

    gen = ReproductionGenerator()

    lines.extend(["", "    [!] Reproduction Scripts:"])

    for issue in issues:
        if issue.get("counterexample"):

            class IssueObj:
                def __init__(self, data: dict[str, Any]) -> None:
                    self.counterexample = data.get("counterexample")

                    self.kind = type("Kind", (), {"name": data.get("kind")})

                    self.message = data.get("message")

                    self.class_name = data.get("class_name")

            script = gen.generate(
                IssueObj(issue),
                issue.get("function_name", "unknown"),
                str(file_path),
                class_name=issue.get("class_name"),
            )

            if script:
                lines.append(f"       + {script}")


def get_symbolic_sarif(results: list[Any]) -> str:
    """Generate SARIF for symbolic scan."""

    from pysymex.reporting.sarif import SARIFGenerator

    generator = SARIFGenerator()

    all_issues: list[dict[str, Any]] = []

    all_files: list[str] = []

    for r in results:
        all_files.append(str(r.file_path))

        for issue in r.issues:
            si = issue.copy()

            si["type"] = issue.get("kind", "UNKNOWN")

            si["file"] = str(r.file_path)

            all_issues.append(si)

    return generator.generate(issues=all_issues, analyzed_files=all_files).to_json()


def _print_static_sarif(issues: list[Any]) -> None:
    """Print static analysis results in SARIF format."""

    from pysymex.reporting.sarif import generate_sarif

    issue_dicts = [i.to_dict() for i in issues]

    sarif_log = generate_sarif(issues=issue_dicts)

    print(sarif_log.to_json())
