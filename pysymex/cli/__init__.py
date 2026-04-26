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

"""Command-line interface for pysymex.
Provides two modes:
1. Single function analysis: pysymex file.py -f function_name
2. Full file/directory scan: pysymex scan path/to/code
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import logging
import sys
import time
from collections.abc import Callable
from importlib.metadata import version as pkg_version
from pathlib import Path
from typing import Protocol, TypeGuard, cast, runtime_checkable

from pysymex._deps import ensure_z3_ready

logger = logging.getLogger(__name__)

try:
    __version__ = pkg_version("pysymex")
except Exception:
    __version__ = "0.1.0a4"


_EXPORTS: dict[str, tuple[str, str]] = {
    "create_parser": ("pysymex.cli.parser", "create_parser"),
    "cmd_scan": ("pysymex.cli.scan", "cmd_scan"),
    "cmd_scan_async": ("pysymex.cli.scan", "cmd_scan_async"),
    "format_static_text_report": ("pysymex.cli.scan", "format_static_text_report"),
    "format_symbolic_text_report": ("pysymex.cli.scan", "format_symbolic_text_report"),
    "get_symbolic_sarif": ("pysymex.cli.scan", "get_symbolic_sarif"),
    "cmd_analyze": ("pysymex.cli.commands", "cmd_analyze"),
    "cmd_benchmark": ("pysymex.cli.commands", "cmd_benchmark"),
    "cmd_check": ("pysymex.cli.commands", "cmd_check"),
    "cmd_concolic": ("pysymex.cli.commands", "cmd_concolic"),
    "cmd_verify": ("pysymex.cli.commands", "cmd_verify"),
    "generate_completion": ("pysymex.cli.commands", "generate_completion"),
}


def __getattr__(name: str) -> object:
    """Getattr."""
    if name in _EXPORTS:
        module_path, attr_name = _EXPORTS[name]
        from importlib import import_module

        mod = import_module(module_path)
        return getattr(mod, attr_name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    """Dir."""
    return [*_EXPORTS.keys(), "main", "__version__", *globals()]


_Namespace = argparse.Namespace


@runtime_checkable
class _IssueLike(Protocol):
    def to_dict(self) -> dict[str, object]: ...


@runtime_checkable
class _SymbolicResultLike(Protocol):
    issues: list[_IssueLike]

    def to_dict(self) -> dict[str, object]: ...


def _is_issue_like_list(value: object) -> TypeGuard[list[_IssueLike]]:
    """Return whether value is a list of issue-like objects."""
    if not isinstance(value, list):
        return False
    issue_items: list[object] = list(value)  # type: ignore[arg-type]  # value is list[Unknown] after isinstance check
    return all(isinstance(item, _IssueLike) for item in issue_items)


_SUBCOMMANDS = frozenset(
    {
        "scan",
        "analyze",
        "verify",
        "concolic",
        "benchmark",
        "check",
    }
)


def _normalize_argv(argv: list[str]) -> list[str]:
    """Translate legacy analyze syntax into modern subcommand form.

    Legacy form:
        pysymex file.py -f function_name

    Modern form:
        pysymex analyze file.py -f function_name
    """
    if not argv:
        return argv

    first = argv[0]
    if first.startswith("-") or first in _SUBCOMMANDS:
        return argv

    tail = argv[1:]
    if "-f" not in tail and "--function" not in tail:
        return argv

    return ["analyze", first, *tail]


def cmd_scan_watch(args: _Namespace) -> int:
    """Execute scan command in watch mode with incremental re-analysis.

    Polls the file system for changes and re-scans modified or new files
    while caching unchanged results.  Supports both *static* and
    *symbolic* analysis modes.

    Args:
        args: Parsed CLI namespace with ``path``, ``mode``, ``format``,
            ``output``, ``recursive``, ``verbose``, ``reproduce``, and
            ``auto`` attributes.

    Returns:
        ``0`` on clean exit (Ctrl-C).
    """
    from pysymex.api import scan_static
    from pysymex.cli.scan import (
        format_static_text_report,
        format_symbolic_text_report,
        get_symbolic_sarif,
    )
    from pysymex.watch import IncrementalAnalyzer

    path = Path(args.path)
    if not path.exists():
        print(f"[X] Error: Path not found: {path}", file=sys.stderr)
        return 1

    print(f"[watch] Watching {path} for changes... (Press Ctrl+C to stop)")

    analyzer = IncrementalAnalyzer()
    file_hashes: dict[Path, str] = {}
    symbolic_results: dict[str, _SymbolicResultLike] = {}
    static_results: dict[str, list[object]] = {}

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
                cached_result = cached.result
                if _is_issue_like_list(cached_result):
                    issue_list: list[object] = [item for item in cached_result]
                    static_results[file_key] = issue_list
                    return len(issue_list)
                return 0
            cached_result = cached.result
            if isinstance(cached_result, _SymbolicResultLike):
                symbolic_results[file_key] = cached_result
                return len(cached_result.issues)
            return 0

        if args.mode == "static":
            issues = scan_static(
                file_path,
                recursive=False,
                verbose=args.verbose,
                min_confidence=0.7,
                show_suppressed=False,
            )
            static_results[file_key] = cast("list[object]", issues)
            analyzer.cache_result(file_key, issues)
            return len(issues)

        from pysymex.scanner import scan_file as _scan_file

        scan_file = cast("Callable[..., _SymbolicResultLike]", _scan_file)

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
            all_issues = [
                issue
                for issues in static_results.values()
                for issue in issues
                if isinstance(issue, _IssueLike)
            ]
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
    """Main CLI entry point.

    Normalises legacy ``pysymex file.py -f func`` invocations, ensures Z3
    is available, then dispatches to the appropriate sub-command handler.

    Args:
        argv: Command-line arguments.  Defaults to ``sys.argv[1:]``.

    Returns:
        Process exit code (``0`` = success).
    """

    if hasattr(sys.stdout, "reconfigure"):
        try:
            cast("io.TextIOWrapper", sys.stdout).reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            logger.debug("Failed to reconfigure stdout encoding", exc_info=True)
    if hasattr(sys.stderr, "reconfigure"):
        try:
            cast("io.TextIOWrapper", sys.stderr).reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            logger.debug("Failed to reconfigure stderr encoding", exc_info=True)

    try:
        ensure_z3_ready()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    from pysymex.cli.parser import create_parser

    parser = create_parser()
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    args = parser.parse_args(_normalize_argv(raw_argv))

    if hasattr(args, "generate_completion") and args.generate_completion:
        from pysymex.cli.commands import generate_completion

        return generate_completion(args.generate_completion)

    if args.command == "scan" and getattr(args, "watch", False):
        return cmd_scan_watch(args)
    elif args.command == "scan" and getattr(args, "use_async", False):
        import asyncio

        from pysymex.cli.scan import cmd_scan_async

        return asyncio.run(cmd_scan_async(args))
    elif args.command == "scan":
        from pysymex.cli.scan import cmd_scan

        return cmd_scan(args)
    elif args.command == "analyze":
        from pysymex.cli.commands import cmd_analyze

        return cmd_analyze(args)
    elif args.command == "verify":
        from pysymex.cli.commands import cmd_verify

        return cmd_verify(args)
    elif args.command == "concolic":
        from pysymex.cli.commands import cmd_concolic

        return cmd_concolic(args)
    elif args.command == "benchmark":
        from pysymex.cli.commands import cmd_benchmark

        return cmd_benchmark(args)
    elif args.command == "check":
        from pysymex.cli.commands import cmd_check

        return cmd_check(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
