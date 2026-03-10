"""
pysymex Scanner - core logic
===============================
Analysis functions, directory scanning, watch-mode CLI entry point.
"""

import argparse
import concurrent.futures
import contextvars
import dataclasses
import logging
import os
import sys
import time
import types
from datetime import datetime
from pathlib import Path

from pysymex.analysis.autotuner import AutoTuner
from pysymex.analysis.detectors import Issue
from pysymex.analysis.detectors.protocols import ScanReporter
from pysymex.analysis.range_analysis import ValueRangeChecker
from pysymex.cli.scan_reporter import ConsoleScanReporter
from pysymex.core.solver import clear_solver_caches
from pysymex.execution.executor import ExecutionConfig, SymbolicExecutor
from pysymex.scanner.types import ScanResult, ScanResultBuilder, ScanSession
from pysymex.watch import FileEventType, FileWatcher

logger = logging.getLogger(__name__)

_session_var: contextvars.ContextVar[ScanSession | None] = contextvars.ContextVar(
    "_session_var",
    default=None,
)


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


def analyze_source(
    content: str,
    file_path: str = "<source>",
    *,
    max_paths: int = 100,
    max_depth: int = 50,
    timeout_seconds: float = 30.0,
) -> ScanResult:
    """Analyse already-loaded source text — pure-ish core (no file I/O).

    This is the functional core of ``analyze_file`` and ``scan_file``.
    It receives *source text* instead of touching the filesystem, so
    callers control where the text comes from.

    Returns:
        A :class:`ScanResult` populated with issues, paths explored, etc.
    """
    builder = ScanResultBuilder(file_path=file_path)
    try:
        code_obj = compile(content, file_path, "exec")
        all_code_with_context = get_code_objects_with_context(code_obj)
        builder.code_objects = len(all_code_with_context)
        config = ExecutionConfig(
            max_paths=max_paths,
            max_depth=max_depth,
            max_iterations=max(50000, max_paths * 100),
            timeout_seconds=timeout_seconds,
        )
        executor = SymbolicExecutor(config=config)
        all_issues: list[Issue] = []
        total_paths = 0
        module_item = all_code_with_context[0] if all_code_with_context else None
        other_items = all_code_with_context[1:] if len(all_code_with_context) > 1 else []
        module_globals: dict[str, object] = {}
        if module_item:
            code, class_name, full_path = module_item
            symbolic_vars = dict.fromkeys(code.co_varnames[: code.co_argcount], "int")
            try:
                exec_result = executor.execute_code(code, symbolic_vars=symbolic_vars)
                module_globals = exec_result.final_locals
                for raw_issue in exec_result.issues:
                    issue_with_context = dataclasses.replace(
                        raw_issue,
                        function_name=code.co_name,
                        class_name=class_name,
                        full_path=full_path,
                    )
                    all_issues.append(issue_with_context)
                total_paths += exec_result.paths_explored
            except Exception:
                logger.debug("Module execution failed for %s", file_path, exc_info=True)
        for code, class_name, full_path in other_items:
            symbolic_vars = dict.fromkeys(code.co_varnames[: code.co_argcount], "int")
            try:
                exec_result = executor.execute_code(
                    code,
                    symbolic_vars=symbolic_vars,
                    initial_globals=module_globals,
                )
                for raw_issue in exec_result.issues:
                    issue_ctx = dataclasses.replace(
                        raw_issue,
                        function_name=code.co_name,
                        class_name=class_name,
                        full_path=full_path,
                    )
                    all_issues.append(issue_ctx)
                total_paths += exec_result.paths_explored
            except Exception:
                logger.debug(
                    "Execution failed for %s in %s", code.co_name, file_path, exc_info=True
                )
        builder.add_paths(total_paths)

        range_checker = ValueRangeChecker()
        seen: set[str] = set()
        for code, class_name, full_path in all_code_with_context:
            try:
                range_warnings = range_checker.check_function(code, file_path)
                for warning in range_warnings:
                    msg = f"[Abstract Interpreter] [{warning.kind}] {warning.message} (Line {warning.line})"
                    if msg not in seen:
                        seen.add(msg)
                        builder.add_issue(
                            {
                                "kind": warning.kind,
                                "message": f"[Abstract Interpreter] {warning.message}",
                                "line": warning.line,
                                "pc": warning.pc,
                                "function_name": code.co_name,
                                "class_name": class_name,
                                "full_path": full_path,
                                "counterexample": None,
                            }
                        )
            except (RuntimeError, TypeError, ValueError):
                logger.debug("Value range analysis failed for %s", code.co_name, exc_info=True)
        for issue in all_issues:
            msg = f"[{issue.kind.name}] {issue.message} (Line {issue.line_number})"
            if msg not in seen:
                seen.add(msg)
                builder.add_issue(
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
    except SyntaxError as e:
        builder.set_error(f"Syntax Error: {e}")
    except Exception as e:
        builder.set_error(f"Analysis Error: {e}")
    return builder.build()


def analyze_file(file_path: Path) -> ScanResult:
    """Run PySyMex analysis on a single file (I/O shell).

    Reads the file and delegates to :func:`analyze_source` for the
    actual analysis. Handles session tracking and console output.
    """
    session = _session_var.get()
    print(f"\n{'=' * 70}")
    print(f"🔍 Scanning: {file_path}")
    print("=" * 70)
    try:
        content = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        result = ScanResult(
            file_path=str(file_path),
            timestamp=datetime.now().isoformat(),
            error=f"Read Error: {e}",
        )
        if session:
            session.add_result(result)
        return result

    result = analyze_source(content, str(file_path))

    if result.issues:
        print(f"\n⚠️  Found {len(result.issues)} potential issues:\n")
        for issue in result.issues:
            print(f"   • [{issue['kind']}] {issue['message']} (Line {issue['line']})")
            if issue["counterexample"]:
                for var, val in issue["counterexample"].items():
                    print(f"       └─ {var} = {val}")
    elif result.error:
        print(f"\n❌ {result.error}")
    else:
        print("\n✅ No issues found!")
    print(
        f"\n   📊 Stats: {result.code_objects} code objects | {result.paths_explored} paths explored"
    )
    if session:
        session.add_result(result)
    return result


def scan_file(
    file_path: str | Path,
    verbose: bool = False,
    max_paths: int = 100,
    timeout: float = 30.0,
    auto_tune: bool = False,
    reporter: ScanReporter | None = None,
    no_cache: bool = False,
    max_iterations: int = 0,
    trace_enabled: bool | None = None,
    trace_output_dir: str | None = None,
    trace_verbosity: str = "delta_only",
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
    session = _session_var.get()
    result = ScanResult(
        file_path=str(file_path),
        timestamp=datetime.now().isoformat(),
    )
    tracer = None
    try:
        content = file_path.read_text(encoding="utf-8")
        code_obj = compile(content, str(file_path), "exec")
        all_code_with_context = get_code_objects_with_context(code_obj)
        result.code_objects = len(all_code_with_context)
        config = ExecutionConfig(
            max_paths=max_paths,
            max_depth=1000,
            max_iterations=max_iterations if max_iterations > 0 else max(100000, max_paths * 200),
            timeout_seconds=timeout,
            enable_solver_cache=not no_cache,
        )
        base_config = config
        executor = SymbolicExecutor(config=config)
        if trace_enabled is not False:
            from pysymex.tracing.schemas import TracerConfig, VerbosityLevel
            from pysymex.tracing.tracer import ExecutionTracer

            verbosity_value = trace_verbosity.strip().lower()
            verbosity = {
                "quiet": VerbosityLevel.QUIET,
                "delta_only": VerbosityLevel.DELTA_ONLY,
                "full": VerbosityLevel.FULL,
            }.get(verbosity_value, VerbosityLevel.DELTA_ONLY)

            cfg_overrides: dict[str, object] = {"verbosity": verbosity}
            if trace_enabled is not None:
                cfg_overrides["enabled"] = trace_enabled
            if trace_output_dir:
                cfg_overrides["output_dir"] = trace_output_dir

            tracer_cfg = TracerConfig.from_env(**cfg_overrides)
            if tracer_cfg.enabled:
                tracer = ExecutionTracer(config=tracer_cfg)
                tracer.start_session(
                    func_name=f"scan:{file_path.stem}",
                    signature_str="(module-scan)",
                    initial_args={},
                    config_snapshot=dataclasses.asdict(config),
                    source_file=str(file_path),
                )
                tracer.install(executor)

        all_issues: list[Issue] = []
        total_paths = 0
        module_item = all_code_with_context[0] if all_code_with_context else None
        other_items = all_code_with_context[1:] if len(all_code_with_context) > 1 else []
        module_globals: dict[str, object] = {}
        if module_item:
            code, class_name, full_path = module_item
            symbolic_vars = dict.fromkeys(code.co_varnames[: code.co_argcount], "int")
            try:
                exec_result = executor.execute_code(code, symbolic_vars=symbolic_vars)
                module_globals = exec_result.final_locals
                for raw_issue in exec_result.issues:
                    processed_issue = dataclasses.replace(
                        raw_issue,
                        function_name=code.co_name,
                        class_name=class_name,
                        full_path=full_path,
                    )
                    all_issues.append(processed_issue)
                total_paths += exec_result.paths_explored
            except Exception as e:
                logger.debug("Module execution failed for %s: %s", str(file_path), e, exc_info=True)
        for code, class_name, full_path in other_items:
            if auto_tune:
                tune_config = AutoTuner.tune(code, base_config)
                tune_config = dataclasses.replace(
                    tune_config,
                    enable_state_merging=base_config.enable_state_merging,
                    enable_caching=base_config.enable_caching,
                    enable_taint_tracking=base_config.enable_taint_tracking,
                )
                executor = SymbolicExecutor(config=tune_config)

            symbolic_vars = dict.fromkeys(code.co_varnames[: code.co_argcount], "int")
            try:
                exec_result = executor.execute_code(
                    code, symbolic_vars=symbolic_vars, initial_globals=module_globals
                )
                for raw_issue in exec_result.issues:
                    processed_issue = dataclasses.replace(
                        raw_issue,
                        function_name=code.co_name,
                        class_name=class_name,
                        full_path=full_path,
                    )
                    all_issues.append(processed_issue)
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
                    msg = f"[Abstract Interpreter] [{warning.kind}] {warning.message} (Line {warning.line})"
                    if msg not in seen:
                        seen.add(msg)
                        result.issues.append(
                            {
                                "kind": warning.kind,
                                "message": f"[Abstract Interpreter] {warning.message}",
                                "line": warning.line,
                                "pc": warning.pc,
                                "function_name": code.co_name,
                                "class_name": class_name,
                                "full_path": full_path,
                                "counterexample": None,
                            }
                        )
            except (RuntimeError, TypeError, ValueError):
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
                if reporter:
                    reporter.on_progress(0, 1, file_path, result)
                else:
                    status_msg = f"{len(result.issues)} issues found" if result.issues else "No issues"
                    print(f"{'⚠️' if result.issues else '✅'} {file_path}: {status_msg}")
    except SyntaxError as e:
        result.error = f"Syntax Error: {e}"
        if reporter:
            reporter.on_error(file_path, result.error)
        elif verbose:
            print(f"\n❌ {result.error}")
    except Exception as e:
        result.error = f"Analysis Error: {e}"
        if reporter:
            reporter.on_error(file_path, result.error)
        elif verbose:
            print(f"\n❌ {result.error}")
    finally:
        if tracer is not None:
            try:
                tracer.end_session()
            except Exception:
                logger.debug("Failed to close trace session for %s", file_path, exc_info=True)
    if session:
        session.add_result(result)
    return result


def scan_directory(
    dir_path: str | Path,
    pattern: str = "**/*.py",
    verbose: bool = True,
    max_paths: int = 200,
    timeout: int = 30,
    workers: int | None = None,
    recursive: bool = False,
    mode: str = "symbolic",
    auto_tune: bool = False,
    reporter: ScanReporter | None = None,
    no_cache: bool = False,
    max_iterations: int = 0,
    trace_enabled: bool | None = None,
    trace_output_dir: str | None = None,
    trace_verbosity: str = "delta_only",
) -> list[ScanResult]:
    """Scan all Python files in a directory for potential bugs."""
    dir_path = Path(dir_path)
    files = sorted(dir_path.glob(pattern))

    if not reporter:
        from pysymex.cli.scan_reporter import ConsoleScanReporter

        reporter = ConsoleScanReporter()

    if files:
        reporter.on_status(f"Scanning {len(files)} Python files in {dir_path}...\n")
    else:
        if verbose and reporter:
            reporter.on_summary([], 0)
        elif verbose:
            print(f"No Python files found in {dir_path}")
        return []

    workers_count = max(1, os.cpu_count() or 1) if workers is None or workers <= 0 else workers

    if workers_count > 1 and len(files) < workers_count * 2:
        workers_count = max(1, len(files) // 2)

    if workers_count <= 1:
        return _scan_sequential(
            files,
            verbose,
            max_paths,
            timeout,
            auto_tune,
            reporter,
            no_cache,
            max_iterations,
            trace_enabled,
            trace_output_dir,
            trace_verbosity,
        )

    return _scan_parallel(
        files,
        workers_count,
        verbose,
        max_paths,
        timeout,
        auto_tune,
        reporter,
        no_cache,
        max_iterations,
        trace_enabled,
        trace_output_dir,
        trace_verbosity,
    )


_PARALLEL_CHUNK = 64


def _scan_sequential(
    files: list[Path],
    verbose: bool,
    max_paths: int,
    timeout: float,
    auto_tune: bool,
    reporter: ScanReporter | None = None,
    no_cache: bool = False,
    max_iterations: int = 0,
    trace_enabled: bool | None = None,
    trace_output_dir: str | None = None,
    trace_verbosity: str = "delta_only",
) -> list[ScanResult]:
    """Scan *files* one-by-one in the current process."""
    results: list[ScanResult] = []
    total = len(files)
    if verbose and not reporter:
        print(f"Scanning {total} file{'s' if total != 1 else ''} sequentially...")
    for i, file_path in enumerate(files, 1):
        if verbose and not reporter:
            print(f"[{i}/{total}] {file_path.name}...", end=" ", flush=True)
        try:
            result = scan_file(
                file_path,
                verbose=False,
                max_paths=max_paths,
                timeout=timeout,
                auto_tune=auto_tune,
                reporter=reporter,
                no_cache=no_cache,
                max_iterations=max_iterations,
                trace_enabled=trace_enabled,
                trace_output_dir=trace_output_dir,
                trace_verbosity=trace_verbosity,
            )
            results.append(result)
            clear_solver_caches()
            if verbose:
                if reporter:
                    reporter.on_progress(i, total, file_path, result)
                else:
                    if result.error:
                        print("\u274c Error")
                    elif result.issues:
                        print(f"\u26a0\ufe0f  {len(result.issues)} issues")
                    else:
                        print("\u2705")
        except Exception as e:
            if verbose:
                if reporter:
                    reporter.on_error(file_path, str(e))
                else:
                    print(f"\u274c Error: {e}")
    if verbose:
        if reporter:
            reporter.on_summary(results, total)
        else:
            _print_scan_summary(results, total)
    return results


def _scan_parallel(
    files: list[Path],
    workers_count: int,
    verbose: bool,
    max_paths: int,
    timeout: float,
    auto_tune: bool,
    reporter: ScanReporter | None = None,
    no_cache: bool = False,
    max_iterations: int = 0,
    trace_enabled: bool | None = None,
    trace_output_dir: str | None = None,
    trace_verbosity: str = "delta_only",
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
    if verbose and not reporter:
        print(f"Scanning {total} file{'s' if total != 1 else ''} using {workers_count} workers...")

    results: list[ScanResult] = []
    completed = 0
    cancelled = False
    scan_errors: list[Exception] = []

    try:
        with concurrent.futures.ProcessPoolExecutor(
            max_workers=workers_count,
        ) as executor:
            future_to_file: dict[concurrent.futures.Future[ScanResult], Path] = {}
            file_iter = iter(files)

            for _ in range(workers_count * 2):
                try:
                    f = next(file_iter)
                    fut = executor.submit(
                        scan_file,
                        file_path=f,
                        verbose=False,
                        max_paths=max_paths,
                        timeout=timeout,
                        auto_tune=auto_tune,
                        no_cache=no_cache,
                        max_iterations=max_iterations,
                        trace_enabled=trace_enabled,
                        trace_output_dir=trace_output_dir,
                        trace_verbosity=trace_verbosity,
                    )
                    future_to_file[fut] = f
                except StopIteration:
                    break

            while future_to_file:
                if cancelled:
                    break

                done, _ = concurrent.futures.wait(
                    future_to_file.keys(), return_when=concurrent.futures.FIRST_COMPLETED
                )

                for future in done:
                    file_path = future_to_file.pop(future)
                    result = None
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as exc:
                        scan_errors.append(exc)
                        if verbose:
                            if reporter:
                                reporter.on_error(file_path, str(exc))
                            else:
                                print(f"❌ Error scanning {file_path.name}: {exc}")

                    completed += 1
                    if verbose:
                        if reporter:
                            reporter.on_progress(completed, total, file_path, result)
                        else:
                            _print_parallel_progress(completed, total, file_path, result)

                    try:
                        f = next(file_iter)
                        fut = executor.submit(
                            scan_file,
                            file_path=f,
                            verbose=False,
                            max_paths=max_paths,
                            timeout=timeout,
                            auto_tune=auto_tune,
                            no_cache=no_cache,
                            max_iterations=max_iterations,
                            trace_enabled=trace_enabled,
                            trace_output_dir=trace_output_dir,
                            trace_verbosity=trace_verbosity,
                        )
                        future_to_file[fut] = f
                    except StopIteration:
                        pass
    except KeyboardInterrupt:
        cancelled = True
        if verbose and not reporter:
            print(f"\n\u26a1 Interrupted \u2013 returning {len(results)} results collected so far.")
    except (RuntimeError, concurrent.futures.process.BrokenProcessPool) as exc:
        logger.warning("Parallel scanning failed (%s), falling back to sequential", exc)
        if verbose and not reporter:
            print("\u26a0\ufe0f  Parallel scanning unavailable, falling back to sequential...")
        return _scan_sequential(
            files,
            verbose,
            max_paths,
            timeout,
            auto_tune,
            reporter,
            no_cache,
            max_iterations,
            trace_enabled,
            trace_output_dir,
            trace_verbosity,
        )

    if scan_errors and not cancelled:
        try:
            raise ExceptionGroup(
                f"scan: {len(scan_errors)} file(s) had errors",
                scan_errors,
            )
        except* OSError as eg:
            logger.warning("%d OS error(s) during parallel scan", len(eg.exceptions))
        except* Exception as eg:
            logger.warning("%d error(s) during parallel scan", len(eg.exceptions))

    if verbose and not cancelled:
        if reporter:
            reporter.on_summary(results, total)
        else:
            _print_scan_summary(results, total)
    return results


def _print_parallel_progress(
    completed: int,
    total: int,
    file_path: Path,
    result: ScanResult | None,
) -> None:
    """Print a single progress line for parallel scanning."""
    pct = completed * 100 // total if total > 0 else 0
    status = "✅"
    if result is None or result.error:
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


def on_file_event(event: object, reporter: ScanReporter | None = None) -> None:
    """Handle a file-system event from the watcher.

    Triggers :func:`analyze_file` for newly created or modified
    ``.py`` files.

    Args:
        event: A watch event with ``event_type`` and ``path`` attributes.
        reporter: Optional reporter for console output.
    """
    if (
        event.event_type in (FileEventType.CREATED, FileEventType.MODIFIED)
        and event.path.suffix == ".py"
    ):
        analyze_file(event.path)


def print_final_summary(reporter: ScanReporter | None = None) -> None:
    """Print a formatted session summary to stdout.

    Reads the current :class:`ScanSession` from *_session_var* and
    displays file counts, issue breakdown, and the log-file path.
    Does nothing if no session is active.
    """
    session = _session_var.get()
    if not session:
        return
    if reporter and hasattr(reporter, "on_session_summary"):
        reporter.on_session_summary(session)
        return
    summary = session.get_summary()
    print(f"\n\n{'=' * 70}")
    print("\U0001f4cb SESSION SUMMARY")
    print("=" * 70)
    print(f"   Files scanned:     {summary['files_scanned']}")
    print(f"   Files with issues: {summary['files_with_issues']}")
    print(f"   Files clean:       {summary['files_clean']}")
    print(f"   Files with errors: {summary['files_error']}")
    print(f"   Total issues:      {summary['total_issues']}")
    print()
    if summary["issue_breakdown"]:
        print("   Issue breakdown:")
        for kind, count in sorted(summary["issue_breakdown"].items(), key=lambda x: -x[1]):
            bar = "\u2588" * min(count, 30)
            print(f"      {kind:<25} {count:>4} {bar}")
    print(f"\n   \U0001f4c1 Log saved to: {session.log_file}")
    print("=" * 70)


def main() -> None:
    """CLI entry point for the scanner's watch mode.

    Parses ``--dir``, ``--log``, ``--watch``, ``--recursive`` arguments,
    performs an initial scan of existing files, and optionally enters
    continuous watch mode via :class:`pysymex.watch.FileWatcher`.
    """
    reporter: ScanReporter = ConsoleScanReporter()

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
    parser.add_argument(
        "--auto-tune",
        "-at",
        action="store_true",
        help="Automatically tune execution parameters based on code complexity",
    )
    parser.add_argument(
        "--max-paths",
        type=int,
        default=200,
        help="Maximum paths to explore (default: 200)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Timeout per file in seconds (default: 30.0)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=0,
        help="Number of worker processes (0=auto)",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable all caching",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=0,
        help="Maximum iterations per function",
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Enable detailed execution tracing (generates JSONL logs)",
    )
    args = parser.parse_args()
    scan_dir = Path(args.dir)
    log_file = Path(args.log) if args.log else None
    if not scan_dir.exists():
        reporter.on_error(scan_dir, f"Directory '{scan_dir}' does not exist")
        sys.exit(1)
    session = ScanSession(log_file=log_file)
    _session_var.set(session)
    pattern = "**/*.py" if args.recursive else "*.py"
    existing_files = list(scan_dir.glob(pattern))
    if existing_files:
        results = scan_directory(
            scan_dir,
            pattern=pattern,
            max_paths=args.max_paths,
            timeout=args.timeout,
            workers=args.workers,
            auto_tune=args.auto_tune,
            reporter=reporter,
            no_cache=args.no_cache,
            max_iterations=args.max_iterations,
            trace_enabled=args.trace,
        )
        if session:
            for r in results:
                session.add_result(r)
    else:
        reporter.on_status(f"No Python files found in {scan_dir}")
    if args.watch:
        reporter.on_status(
            "\n\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557\n"
            "\u2551                   PySyMex Scanner - Watch Mode                     \u2551\n"
            "\u2551  Press Ctrl+C to stop and see summary.                               \u2551\n"
            "\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d\n"
        )
        watcher = FileWatcher(paths=[scan_dir], patterns=["*.py"])
        watcher.on_change(lambda evt: on_file_event(evt, reporter=reporter))
        watcher.start()
        try:
            reporter.on_status("\U0001f441\ufe0f  Watching for file changes...")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            reporter.on_status("\n\nStopping watcher...")
            watcher.stop()
    print_final_summary(reporter=reporter)
    reporter.on_status("\nDone.")


if __name__ == "__main__":
    main()
