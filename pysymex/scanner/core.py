"""
pysymex Scanner – core logic
===============================
Analysis functions, directory scanning, watch-mode CLI entry point.
"""

import argparse

import concurrent.futures

import logging

import os

import sys

import types

from datetime import datetime

from pathlib import Path

from typing import Any


from pysymex.analysis.autotuner import AutoTuner

from pysymex.analysis.detectors import Issue

from pysymex.analysis.range_analysis import ValueRangeChecker

from pysymex.core.solver import clear_solver_caches

from pysymex.execution.executor import ExecutionConfig, SymbolicExecutor

from pysymex.scanner.types import ScanResult, ScanSession

logger = logging.getLogger(__name__)


session: ScanSession | None = None


def get_code_objects_with_context(
    code: types.CodeType, parent_path: str | None = None
) -> list[tuple[types.CodeType, str | None, str | None]]:
    """
    Recursively extract all code objects with their full hierarchical path.

    Returns:
        List of tuples: (code_object, immediate_parent, full_path)
        - immediate_parent: Direct parent name (for class instantiation)
        - full_path: Full dotted path (for nested class imports like Outer.Inner)
    """

    current_name: str = code.co_name

    if current_name == "<module>":
        full_path: str | None = None

        immediate_parent: str | None = None

    else:
        full_path = f"{parent_path}.{current_name}" if parent_path else current_name

        immediate_parent = parent_path

    results: list[tuple[types.CodeType, str | None, str | None]] = [
        (code, immediate_parent, full_path)
    ]

    child_parent: str | None = full_path if current_name != "<module>" else None

    for const in code.co_consts:
        if hasattr(const, "co_code"):
            results.extend(get_code_objects_with_context(const, child_parent))

    return results


def analyze_file(file_path: Path) -> ScanResult:
    """Run PySyMex analysis on a single file."""

    global session

    print(f"\n{'=' * 70}")

    print(f"🔍 Scanning: {file_path}")

    print("=" * 70)

    result = ScanResult(
        file_path=str(file_path),
        timestamp=datetime.now().isoformat(),
    )

    try:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()

        code_obj = compile(content, str(file_path), "exec")

        all_code_with_context = get_code_objects_with_context(code_obj)

        result.code_objects = len(all_code_with_context)

        config = ExecutionConfig(
            max_paths=100, max_depth=50, max_iterations=5000, timeout_seconds=30.0
        )

        executor = SymbolicExecutor(config=config)

        all_issues: list[Issue] = []

        total_paths = 0

        module_item = all_code_with_context[0] if all_code_with_context else None

        other_items = all_code_with_context[1:] if len(all_code_with_context) > 1 else []

        module_globals: dict[str, Any] = {}

        if module_item:
            code, class_name, full_path = module_item

            symbolic_vars = dict.fromkeys(code.co_varnames[: code.co_argcount], "int")

            try:
                exec_result = executor.execute_code(code, symbolic_vars=symbolic_vars)

                module_globals = exec_result.final_locals

                for issue in exec_result.issues:
                    issue.function_name = code.co_name

                    issue.class_name = class_name

                    issue.full_path = full_path

                all_issues.extend(exec_result.issues)

                total_paths += exec_result.paths_explored

            except Exception as e:
                print(f"DEBUG EXCEPTION in module {code.co_name}: {e}")

        for code, class_name, full_path in other_items:
            symbolic_vars = dict.fromkeys(code.co_varnames[: code.co_argcount], "int")

            try:
                exec_result = executor.execute_code(
                    code, symbolic_vars=symbolic_vars, initial_globals=module_globals
                )

                for issue in exec_result.issues:
                    issue.function_name = code.co_name

                    issue.class_name = class_name

                    issue.full_path = full_path

                all_issues.extend(exec_result.issues)

                total_paths += exec_result.paths_explored

            except Exception as e:
                print(f"DEBUG EXCEPTION in {code.co_name}: {e}")

                import traceback

                traceback.print_exc()

        result.paths_explored = total_paths

        range_checker = ValueRangeChecker()

        seen: set[str] = set()

        for code, class_name, full_path in all_code_with_context:
            try:
                range_warnings = range_checker.check_function(code, str(file_path))

                for warning in range_warnings:
                    msg = f"[{warning.kind}] {warning.message} (Line {warning.line})"

                    if msg not in seen:
                        seen.add(msg)

                        result.issues.append(
                            {
                                "kind": warning.kind,
                                "message": warning.message,
                                "line": warning.line,
                                "pc": warning.pc,
                                "function_name": code.co_name,
                                "class_name": class_name,
                                "full_path": full_path,
                                "counterexample": None,
                            }
                        )

            except Exception:
                logger.debug("Value range analysis failed for %s", code.co_name, exc_info=True)

        for issue in all_issues:
            msg = f"[{issue.kind.name}] {issue.message} (Line {issue.line_number})"

            if msg not in seen:
                seen.add(msg)

                result.issues.append(
                    {
                        "kind": issue.kind.name,
                        "message": issue.message,
                        "line": issue.line_number,
                        "pc": issue.pc,
                        "function_name": issue.function_name,
                        "class_name": getattr(issue, "class_name", None),
                        "full_path": getattr(issue, "full_path", None),
                        "counterexample": issue.get_counterexample(),
                    }
                )

        if result.issues:
            print(f"\n⚠️  Found {len(result.issues)} potential issues:\n")

            for issue in result.issues:
                print(f"   • [{issue['kind']}] {issue['message']} (Line {issue['line']})")

                if issue["counterexample"]:
                    for var, val in issue["counterexample"].items():
                        print(f"       └─ {var} = {val}")

        else:
            print("\n✅ No issues found!")

        print(
            f"\n   📊 Stats: {result.code_objects} code objects | {result.paths_explored} paths explored"
        )

    except SyntaxError as e:
        result.error = f"Syntax Error: {e}"

        print(f"\n❌ {result.error}")

    except Exception as e:
        result.error = f"Analysis Error: {e}"

        print(f"\n❌ {result.error}")

    if session:
        session.add_result(result)

    return result


def scan_file(
    file_path: str | Path,
    verbose: bool = False,
    max_paths: int = 100,
    timeout: float = 30.0,
    auto_tune: bool = False,
) -> ScanResult:
    """
    Scan a single Python file for potential bugs.
    Args:
        file_path: Path to the Python file
        verbose: Print detailed output
        max_paths: Maximum paths per function
        timeout: Timeout in seconds
        auto_tune: Automatically adjust config based on complexity
    Returns:
        ScanResult with issues found
    Example:
        >>> result = scan_file("mycode.py")
        >>> for issue in result.issues:
        ...     print(f"{issue['kind']}: {issue['message']}")
    """

    file_path = Path(file_path)

    result = ScanResult(
        file_path=str(file_path),
        timestamp=datetime.now().isoformat(),
    )

    try:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()

        code_obj = compile(content, str(file_path), "exec")

        all_code_with_context = get_code_objects_with_context(code_obj)

        result.code_objects = len(all_code_with_context)

        config = ExecutionConfig(
            max_paths=max_paths, max_depth=50, max_iterations=5000, timeout_seconds=timeout
        )

        base_config = config

        executor = SymbolicExecutor(config=config)

        all_issues: list[Issue] = []

        total_paths = 0

        module_item = all_code_with_context[0] if all_code_with_context else None

        other_items = all_code_with_context[1:] if len(all_code_with_context) > 1 else []

        module_globals: dict[str, Any] = {}

        if module_item:
            code, class_name, full_path = module_item

            symbolic_vars = dict.fromkeys(code.co_varnames[: code.co_argcount], "int")

            try:
                exec_result = executor.execute_code(code, symbolic_vars=symbolic_vars)

                module_globals = exec_result.final_locals

                for issue in exec_result.issues:
                    issue.function_name = code.co_name

                    issue.class_name = class_name

                    issue.full_path = full_path

                all_issues.extend(exec_result.issues)

                total_paths += exec_result.paths_explored

            except Exception as e:
                if verbose:
                    print(f"DEBUG: Module execution failed: {e}")

        for code, class_name, full_path in other_items:
            if auto_tune:
                tune_config = AutoTuner.tune(code, base_config)

                tune_config.enable_state_merging = base_config.enable_state_merging

                tune_config.enable_caching = base_config.enable_caching

                tune_config.enable_taint_tracking = base_config.enable_taint_tracking

                executor = SymbolicExecutor(config=tune_config)

            symbolic_vars = dict.fromkeys(code.co_varnames[: code.co_argcount], "int")

            try:
                exec_result = executor.execute_code(
                    code, symbolic_vars=symbolic_vars, initial_globals=module_globals
                )

                for issue in exec_result.issues:
                    issue.function_name = code.co_name

                    issue.class_name = class_name

                    issue.full_path = full_path

                all_issues.extend(exec_result.issues)

                total_paths += exec_result.paths_explored

            except Exception:
                logger.debug("Symbolic execution failed for %s", code.co_name, exc_info=True)

        result.paths_explored = total_paths

        range_checker = ValueRangeChecker()

        seen: set[str] = set()

        for code, class_name, full_path in all_code_with_context:
            try:
                range_warnings = range_checker.check_function(code, str(file_path))

                for warning in range_warnings:
                    msg = f"[{warning.kind}] {warning.message} (Line {warning.line})"

                    if msg not in seen:
                        seen.add(msg)

                        result.issues.append(
                            {
                                "kind": warning.kind,
                                "message": warning.message,
                                "line": warning.line,
                                "pc": warning.pc,
                                "function_name": code.co_name,
                                "class_name": class_name,
                                "full_path": full_path,
                                "counterexample": None,
                            }
                        )

            except Exception:
                logger.debug("Value range analysis failed for %s", code.co_name, exc_info=True)

        for issue in all_issues:
            msg = f"[{issue.kind.name}] {issue.message} (Line {issue.line_number})"

            if msg not in seen:
                seen.add(msg)

                result.issues.append(
                    {
                        "kind": issue.kind.name,
                        "message": issue.message,
                        "line": issue.line_number,
                        "pc": issue.pc,
                        "function_name": issue.function_name,
                        "class_name": getattr(issue, "class_name", None),
                        "full_path": getattr(issue, "full_path", None),
                        "counterexample": issue.get_counterexample(),
                    }
                )

        if verbose:
            if result.issues:
                print(f"⚠️  {file_path}: {len(result.issues)} issues found")

            else:
                print(f"✅ {file_path}: No issues")

    except SyntaxError as e:
        result.error = f"Syntax Error: {e}"

        print(f"\n❌ {result.error}")

    except Exception as e:
        result.error = f"Analysis Error: {e}"

        print(f"\n❌ {result.error}")

    if session:
        session.add_result(result)

    return result


def scan_directory(
    dir_path: str | Path,
    pattern: str = "**/*.py",
    verbose: bool = True,
    max_paths: int = 100,
    timeout: float = 30.0,
    workers: int | None = None,
    auto_tune: bool = False,
) -> list[ScanResult]:
    """Scan all Python files in a directory for potential bugs.

    Uses ``ProcessPoolExecutor`` for true multi-core parallelism when
    *workers > 1*.  Each worker runs in its own process with independent
    Z3 context, so there is no GIL contention.

    For large directories (hundreds/thousands of files) the work is
    submitted in **chunks** to avoid unbounded memory growth from queuing
    all futures at once.

    Args:
        dir_path: Path to directory
        pattern: Glob pattern for files (default: ``**/*.py`` for recursive)
        verbose: Print progress
        max_paths: Maximum paths per function
        timeout: Timeout per file
        workers: Number of worker processes.
            *  ``None`` or ``0`` -- auto-detect (CPU count, min 1)
            *  ``1`` -- sequential (no subprocess overhead)
            *  ``N`` -- use *N* worker processes
        auto_tune: Automatically adjust config per function
    Returns:
        List of :class:`ScanResult`, one per file.
    """

    dir_path = Path(dir_path)

    files = sorted(dir_path.glob(pattern))

    if not files:
        if verbose:
            print(f"No Python files found in {dir_path}")

        return []

    if workers is None or workers <= 0:
        workers_count = max(1, (os.cpu_count() or 1))

    else:
        workers_count = workers

    if workers_count > 1 and len(files) < workers_count * 2:
        workers_count = max(1, len(files) // 2)

    if workers_count <= 1:
        return _scan_sequential(files, verbose, max_paths, timeout, auto_tune)

    return _scan_parallel(
        files,
        workers_count,
        verbose,
        max_paths,
        timeout,
        auto_tune,
    )


_PARALLEL_CHUNK = 64


def _scan_sequential(
    files: list[Path],
    verbose: bool,
    max_paths: int,
    timeout: float,
    auto_tune: bool,
) -> list[ScanResult]:
    """Scan *files* one-by-one in the current process."""

    results: list[ScanResult] = []

    total = len(files)

    if verbose:
        print(f"Scanning {total} file{'s' if total != 1 else ''} sequentially...")

    for i, file_path in enumerate(files, 1):
        if verbose:
            print(f"[{i}/{total}] {file_path.name}...", end=" ", flush=True)

        try:
            result = scan_file(
                file_path,
                verbose=False,
                max_paths=max_paths,
                timeout=timeout,
                auto_tune=auto_tune,
            )

            results.append(result)

            clear_solver_caches()

            if verbose:
                if result.error:
                    print("❌ Error")

                elif result.issues:
                    print(f"⚠️  {len(result.issues)} issues")

                else:
                    print("✅")

        except Exception as e:
            if verbose:
                print(f"❌ Error: {e}")

    if verbose:
        _print_scan_summary(results, total)

    return results


def _scan_parallel(
    files: list[Path],
    workers_count: int,
    verbose: bool,
    max_paths: int,
    timeout: float,
    auto_tune: bool,
) -> list[ScanResult]:
    """Scan *files* across multiple worker processes.

    Uses chunked submission to cap memory usage.  Each chunk of
    ``_PARALLEL_CHUNK`` files is submitted; we wait for the whole chunk
    to finish before submitting the next one.  This keeps at most
    ``_PARALLEL_CHUNK`` futures alive at any time.

    Handles *KeyboardInterrupt* gracefully by cancelling pending futures
    and returning whatever results have been collected so far.
    """

    total = len(files)

    if verbose:
        print(
            f"Scanning {total} file{'s' if total != 1 else ''} " f"using {workers_count} workers..."
        )

    results: list[ScanResult] = []

    completed = 0

    cancelled = False

    try:
        with concurrent.futures.ProcessPoolExecutor(
            max_workers=workers_count,
        ) as executor:
            for chunk_start in range(0, total, _PARALLEL_CHUNK):
                if cancelled:
                    break

                chunk = files[chunk_start : chunk_start + _PARALLEL_CHUNK]

                future_to_file: dict[concurrent.futures.Future[ScanResult], Path] = {
                    executor.submit(
                        scan_file,
                        file_path=f,
                        verbose=False,
                        max_paths=max_paths,
                        timeout=timeout,
                        auto_tune=auto_tune,
                    ): f
                    for f in chunk
                }

                for future in concurrent.futures.as_completed(future_to_file):
                    file_path = future_to_file[future]

                    result: ScanResult | None = None

                    try:
                        result = future.result()

                        results.append(result)

                    except Exception as exc:
                        if verbose:
                            print(f"❌ Error scanning {file_path.name}: {exc}")

                    completed += 1

                    if verbose:
                        _print_parallel_progress(
                            completed,
                            total,
                            file_path,
                            result,
                        )

    except KeyboardInterrupt:
        cancelled = True

        if verbose:
            print(f"\n⚡ Interrupted – returning {len(results)} results collected so far.")

    except (RuntimeError, concurrent.futures.process.BrokenProcessPool) as exc:
        logger.warning("Parallel scanning failed (%s), falling back to sequential", exc)

        if verbose:
            print(f"⚠️  Parallel scanning unavailable, falling back to sequential...")

        return _scan_sequential(files, verbose, max_paths, timeout, auto_tune)

    if verbose and not cancelled:
        _print_scan_summary(results, total)

    return results


def _print_parallel_progress(
    completed: int,
    total: int,
    file_path: Path,
    result: ScanResult | None,
) -> None:
    """Print a single progress line for parallel scanning."""

    pct = completed * 100 // total

    status = "✅"

    if result is None:
        status = "❌"

    elif result.error:
        status = "❌"

    elif result.issues:
        status = f"⚠️  {len(result.issues)}"

    print(f"[{completed}/{total}] ({pct}%) {file_path.name} {status}")


def _print_scan_summary(results: list[ScanResult], total_files: int) -> None:
    """Print end-of-scan summary."""

    total_issues = sum(len(r.issues) for r in results)

    files_with_issues = sum(1 for r in results if r.issues)

    errors = sum(1 for r in results if r.error)

    print(f"\nSummary: {total_issues} issues in {files_with_issues}/{len(results)} files", end="")

    if errors:
        print(f" ({errors} errors)")

    else:
        print()

    if len(results) < total_files:
        print(f"  ⚠️  {total_files - len(results)} file(s) could not be scanned")


def on_file_event(event: Any):
    """Handle file system events."""

    from pysymex.watch import FileEventType

    if event.event_type in (FileEventType.CREATED, FileEventType.MODIFIED):
        if event.path.suffix == ".py":
            analyze_file(event.path)


def print_final_summary():
    """Print final session summary."""

    global session

    if not session:
        return

    summary = session.get_summary()

    print(f"\n\n{'=' * 70}")

    print("📋 SESSION SUMMARY")

    print("=" * 70)

    print(f"   Files scanned:     {summary['files_scanned']}")

    print(f"   Files with issues: {summary['files_with_issues']}")

    print(f"   Files clean:       {summary['files_clean']}")

    print(f"   Files with errors: {summary['files_error']}")

    print(f"   Total issues:      {summary['total_issues']}")

    print("")

    if summary["issue_breakdown"]:
        print("   Issue breakdown:")

        for kind, count in sorted(summary["issue_breakdown"].items(), key=lambda x: -x[1]):
            bar = "█" * min(count, 30)

            print(f"      {kind:<25} {count:>4} {bar}")

    print(f"\n   📁 Log saved to: {session.log_file}")

    print("=" * 70)


def main():
    """CLI entry point for watch mode."""

    global session

    from pysymex.watch import FileWatcher

    parser = argparse.ArgumentParser(description="pysymex Scanner")

    parser.add_argument(
        "--dir",
        "-d",
        type=str,
        default=".",
        help="Directory to scan/watch (default: current directory)",
    )

    parser.add_argument(
        "--log",
        "-l",
        type=str,
        default=None,
        help="Log file path (default: scan_log_TIMESTAMP.json)",
    )

    parser.add_argument(
        "--watch",
        "-w",
        action="store_true",
        help="Watch mode: continuously monitor for file changes",
    )

    parser.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        default=True,
        help="Scan subdirectories recursively (default: True)",
    )

    args = parser.parse_args()

    scan_dir = Path(args.dir)

    log_file = Path(args.log) if args.log else None

    if not scan_dir.exists():
        print(f"Error: Directory '{scan_dir}' does not exist")

        sys.exit(1)

    session = ScanSession(log_file=log_file)

    pattern = "**/*.py" if args.recursive else "*.py"

    existing_files = list(scan_dir.glob(pattern))

    if existing_files:
        print(f"Scanning {len(existing_files)} Python files in {scan_dir}...\n")

        for f in sorted(existing_files):
            analyze_file(f)

    else:
        print(f"No Python files found in {scan_dir}")

    if args.watch:
        print("\n╔══════════════════════════════════════════════════════════════════════╗")

        print("║                   PySyMex Scanner - Watch Mode                     ║")

        print("╠══════════════════════════════════════════════════════════════════════╣")

        print(f"║  Watching: {str(scan_dir):<56} ║")

        print(f"║  Log:      {str(session.log_file):<56} ║")

        print("║  Press Ctrl+C to stop and see summary.                               ║")

        print("╚══════════════════════════════════════════════════════════════════════╝\n")

        watcher = FileWatcher(paths=[scan_dir], patterns=["*.py"])

        watcher.on_change(on_file_event)

        watcher.start()

        try:
            print("👁️  Watching for file changes...")

            while True:
                import time

                time.sleep(1)

        except KeyboardInterrupt:
            print("\n\nStopping watcher...")

            watcher.stop()

    print_final_summary()

    print("\nDone.")


if __name__ == "__main__":
    main()
