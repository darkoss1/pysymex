"""Command-line interface for pysymex.
Provides two modes:
1. Single function analysis: PySyMex file.py -f function_name
2. Full file/directory scan: PySyMex scan path/to/code
"""

from __future__ import annotations


import hashlib

import json

import logging

import sys

import time

from pathlib import Path

from typing import Any


from importlib.metadata import PackageNotFoundError

from importlib.metadata import version as pkg_version


from pysymex._deps import ensure_z3_ready

logger = logging.getLogger(__name__)


try:
    __version__ = pkg_version("pysymex")

except PackageNotFoundError:
    __version__ = "0.1.0a0"

from pysymex.cli.parser import create_parser

from pysymex.cli.scan import (
    cmd_scan,
    format_static_text_report,
    format_symbolic_text_report,
    get_symbolic_sarif,
)

from pysymex.cli.commands import (
    cmd_analyze,
    cmd_benchmark,
    cmd_check,
    cmd_concolic,
    cmd_verify,
    generate_completion,
)

__all__ = [
    "cmd_analyze",
    "cmd_benchmark",
    "cmd_check",
    "cmd_scan",
    "cmd_scan_watch",
    "cmd_verify",
    "create_parser",
    "generate_completion",
    "main",
]


import argparse

_Namespace = argparse.Namespace


def cmd_scan_watch(args: _Namespace) -> int:
    """Execute scan command in watch mode with incremental re-analysis."""

    from pysymex.api import scan_static

    from pysymex.watch import IncrementalAnalyzer

    path = Path(args.path)

    if not path.exists():
        print(f"\u274c Error: Path not found: {path}", file=sys.stderr)

        return 1

    print(f"[watch] Watching {path} for changes... (Press Ctrl+C to stop)")

    analyzer = IncrementalAnalyzer()

    file_hashes: dict[Path, str] = {}

    symbolic_results: dict[str, Any] = {}

    static_results: dict[str, list[Any]] = {}

    def key_of(file_path: Path) -> str:
        return str(file_path.resolve())

    def compute_hash(file_path: Path) -> str | None:
        try:
            return hashlib.sha256(file_path.read_bytes()).hexdigest()

        except OSError:
            return None

    def get_files_to_watch() -> list[Path]:
        """Get sorted list of Python files to watch."""

        if path.is_file():
            return [path]

        pattern = "**/*.py" if args.recursive else "*.py"

        return sorted(p for p in path.glob(pattern) if p.is_file())

    def scan_one(file_path: Path) -> int:
        """Scan one file, using cache if unchanged."""

        file_key = key_of(file_path)

        cached = analyzer.get_cached(file_key)

        if cached is not None:
            if args.mode == "static":
                static_results[file_key] = cached.result

                return len(cached.result)

            symbolic_results[file_key] = cached.result

            return len(cached.result.issues)

        if args.mode == "static":
            issues = scan_static(
                file_path,
                recursive=False,
                verbose=args.verbose,
                min_confidence=0.7,
                show_suppressed=False,
            )

            static_results[file_key] = issues

            analyzer.cache_result(file_key, issues)

            return len(issues)

        from pysymex.scanner import scan_file

        result = scan_file(
            file_path,
            verbose=args.verbose,
            max_paths=args.max_paths,
            timeout=args.timeout,
            auto_tune=args.auto,
        )

        symbolic_results[file_key] = result

        analyzer.cache_result(file_key, result)

        return len(result.issues)

    def remove_file(file_path: Path) -> None:
        """Drop deleted file from incremental/cache state."""

        file_key = key_of(file_path)

        analyzer.invalidate(file_key)

        symbolic_results.pop(file_key, None)

        static_results.pop(file_key, None)

    def emit_report() -> None:
        """Render full report from cached latest results."""

        if args.mode == "static":
            all_issues = [issue for issues in static_results.values() for issue in issues]

            total_issues = len(all_issues)

            if args.format == "json":
                output_data = {
                    "pysymex_version": __version__,
                    "mode": "static",
                    "watch_mode": True,
                    "files_scanned": len(static_results),
                    "total_issues": total_issues,
                    "issues": [i.to_dict() for i in all_issues],
                }

                output = json.dumps(output_data, indent=2, default=str)

            elif args.format == "sarif":
                from pysymex.reporting.sarif import generate_sarif

                issue_dicts = [i.to_dict() for i in all_issues]

                output = generate_sarif(issues=issue_dicts).to_json()

            else:
                output = format_static_text_report(all_issues, total_issues)

        else:
            ordered_keys = sorted(symbolic_results.keys())

            results = [symbolic_results[k] for k in ordered_keys]

            total_issues = sum(len(r.issues) for r in results)

            if args.format == "json":
                output_data = {
                    "pysymex_version": __version__,
                    "mode": "symbolic",
                    "watch_mode": True,
                    "files_scanned": len(results),
                    "total_issues": total_issues,
                    "results": [r.to_dict() for r in results],
                }

                output = json.dumps(output_data, indent=2, default=str)

            elif args.format == "sarif":
                output = get_symbolic_sarif(results)

            else:
                output = format_symbolic_text_report(results, total_issues, args.reproduce)

        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")

            if args.verbose:
                print(f"[watch] Report saved to: {args.output}")

        else:
            print(output)

    def detect_changes() -> tuple[list[Path], list[Path], list[Path]]:
        """Detect created, modified, and deleted files by content hash."""

        current_files = set(get_files_to_watch())

        created: list[Path] = []

        modified: list[Path] = []

        deleted: list[Path] = []

        for file_path in current_files:
            new_hash = compute_hash(file_path)

            if new_hash is None:
                continue

            old_hash = file_hashes.get(file_path)

            if old_hash is None:
                created.append(file_path)

            elif old_hash != new_hash:
                modified.append(file_path)

            file_hashes[file_path] = new_hash

        for file_path in list(file_hashes.keys()):
            if file_path not in current_files:
                deleted.append(file_path)

                del file_hashes[file_path]

        return sorted(created), sorted(modified), sorted(deleted)

    print("\n[watch] Initial scan...")

    initial_files = get_files_to_watch()

    for file_path in initial_files:
        issue_count = scan_one(file_path)

        file_hash = compute_hash(file_path)

        if file_hash is not None:
            file_hashes[file_path] = file_hash

        if args.verbose:
            print(f"   {file_path.name}: {issue_count} issue(s)")

    emit_report()

    try:
        while True:
            time.sleep(1)

            created, modified, deleted = detect_changes()

            if not created and not modified and not deleted:
                continue

            print(f"\n{'=' * 60}")

            print("[watch] Incremental re-scan triggered")

            print(f"{'=' * 60}")

            for file_path in deleted:
                remove_file(file_path)

                print(f"[watch] Deleted: {file_path}")

            for file_path in created:
                issue_count = scan_one(file_path)

                print(f"[watch] Scanned new file: {file_path} ({issue_count} issue(s))")

            for file_path in modified:
                analyzer.invalidate(key_of(file_path))

                issue_count = scan_one(file_path)

                print(f"[watch] Re-scanned changed file: {file_path} ({issue_count} issue(s))")

            emit_report()

    except KeyboardInterrupt:
        print("\n[watch] Stopping watch mode.")

        return 0


def main(argv: list[str] | None = None) -> int:
    """Main entry point."""

    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")

        except Exception:
            logger.debug("Failed to reconfigure stdout encoding", exc_info=True)

    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")

        except Exception:
            logger.debug("Failed to reconfigure stderr encoding", exc_info=True)

    try:
        ensure_z3_ready()

    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)

        return 2

    parser = create_parser()

    args = parser.parse_args(argv)

    if hasattr(args, "generate_completion") and args.generate_completion:
        return generate_completion(args.generate_completion)

    if args.command == "scan" and getattr(args, "watch", False):
        return cmd_scan_watch(args)

    elif args.command == "scan":
        return cmd_scan(args)

    elif args.command == "analyze":
        return cmd_analyze(args)

    elif args.command == "verify":
        return cmd_verify(args)

    elif args.command == "concolic":
        return cmd_concolic(args)

    elif args.command == "benchmark":
        return cmd_benchmark(args)

    elif args.command == "check":
        return cmd_check(args)

    if args.legacy_file and args.legacy_function:
        args.command = "analyze"

        args.file = args.legacy_file

        args.function = args.legacy_function

        args.args = None

        return cmd_analyze(args)

    parser.print_help()

    return 0


if __name__ == "__main__":
    sys.exit(main())
