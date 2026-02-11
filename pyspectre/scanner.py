"""
PySpectre Scanner
=================
File and directory scanning functionality for PySpectre.
Usage as module:
    from pyspectre import scan_file, scan_directory
    results = scan_file("path/to/file.py")
    results = scan_directory("path/to/folder")
Usage as CLI:
    python -m pyspectre.scanner [--dir FOLDER] [--log LOG_FILE]
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from pyspectre.execution.executor import ExecutionConfig, SymbolicExecutor
from pyspectre.analysis.autotuner import AutoTuner
import concurrent.futures
import os


@dataclass
class ScanResult:
    """Result of scanning a single file."""

    file_path: str
    timestamp: str
    issues: list[dict[str, Any]] = field(default_factory=list)
    code_objects: int = 0
    paths_explored: int = 0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file_path,
            "timestamp": self.timestamp,
            "issues": self.issues,
            "code_objects": self.code_objects,
            "paths_explored": self.paths_explored,
            "error": self.error,
        }

    def __repr__(self) -> str:
        return f"ScanResult({self.file_path}, issues={len(self.issues)}, error={self.error})"


class ScanSession:
    """Tracks all scans in a session."""

    def __init__(self, log_file: Path | None = None):
        self.results: list[ScanResult] = []
        self.start_time = datetime.now()
        self.log_file = log_file or Path(
            f"scan_log_{self.start_time.strftime('%Y%m%d_%H%M%S')}.json"
        )

    def add_result(self, result: ScanResult):
        self.results.append(result)
        self._save_log()

    def _save_log(self):
        """Save results to log file."""
        log_data = {
            "session_start": self.start_time.isoformat(),
            "last_update": datetime.now().isoformat(),
            "total_files": len(self.results),
            "total_issues": sum(len(r.issues) for r in self.results),
            "scans": [r.to_dict() for r in self.results],
        }
        with open(self.log_file, "w", encoding="utf-8") as f:
            json.dump(log_data, f, indent=2)

    def get_summary(self) -> dict[str, Any]:
        """Get session summary statistics."""
        total_issues = sum(len(r.issues) for r in self.results)
        issue_counts = {}
        for r in self.results:
            for issue in r.issues:
                kind = issue.get("kind", "UNKNOWN")
                issue_counts[kind] = issue_counts.get(kind, 0) + 1
        return {
            "files_scanned": len(self.results),
            "total_issues": total_issues,
            "issue_breakdown": issue_counts,
            "files_with_issues": sum(1 for r in self.results if r.issues),
            "files_clean": sum(1 for r in self.results if not r.issues and not r.error),
            "files_error": sum(1 for r in self.results if r.error),
        }


session: ScanSession | None = None


def get_code_objects_with_context(code, parent_path=None):
    """
    Recursively extract all code objects with their full hierarchical path.

    Returns:
        List of tuples: (code_object, immediate_parent, full_path)
        - immediate_parent: Direct parent name (for class instantiation)
        - full_path: Full dotted path (for nested class imports like Outer.Inner)
    """
    current_name = code.co_name
    if current_name == "<module>":
        full_path = None
        immediate_parent = None
    else:
        full_path = f"{parent_path}.{current_name}" if parent_path else current_name
        immediate_parent = parent_path
    results = [(code, immediate_parent, full_path)]
    child_parent = full_path if current_name != "<module>" else None
    for const in code.co_consts:
        if hasattr(const, "co_code"):
            results.extend(get_code_objects_with_context(const, child_parent))
    return results


def analyze_file(file_path: Path) -> ScanResult:
    """Run PySpectre analysis on a single file."""
    global session
    print(f"\\n{'=' * 70}")
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
        all_issues = []
        total_paths = 0
        module_item = all_code_with_context[0] if all_code_with_context else None
        other_items = all_code_with_context[1:] if len(all_code_with_context) > 1 else []
        module_globals = {}
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
        seen = set()
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
            print(f"\\n⚠️  Found {len(result.issues)} potential issues:\\n")
            for issue in result.issues:
                print(f"   • [{issue['kind']}] {issue['message']} (Line {issue['line']})")
                if issue["counterexample"]:
                    for var, val in issue["counterexample"].items():
                        print(f"       └─ {var} = {val}")
        else:
            print("\\n✅ No issues found!")
        print(
            f"\\n   📊 Stats: {result.code_objects} code objects | {result.paths_explored} paths explored"
        )
    except SyntaxError as e:
        result.error = f"Syntax Error: {e}"
        print(f"\\n❌ {result.error}")
    except Exception as e:
        result.error = f"Analysis Error: {e}"
        print(f"\\n❌ {result.error}")
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
        all_issues = []
        total_paths = 0
        module_item = all_code_with_context[0] if all_code_with_context else None
        other_items = all_code_with_context[1:] if len(all_code_with_context) > 1 else []
        module_globals = {}
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
            else:
                executor = SymbolicExecutor(config=config)
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
                pass
        result.paths_explored = total_paths
        seen = set()
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
        print(f"\\n❌ {result.error}")
    except Exception as e:
        result.error = f"Analysis Error: {e}"
        print(f"\\n❌ {result.error}")
    if session:
        session.add_result(result)
    return result


def scan_directory(
    dir_path: str | Path,
    pattern: str = "**/*.py",
    verbose: bool = True,
    max_paths: int = 100,
    timeout: float = 30.0,
    workers: int = None,
    auto_tune: bool = False,
) -> list[ScanResult]:
    """
    Scan all Python files in a directory for potential bugs in parallel.
    Args:
        dir_path: Path to directory
        pattern: Glob pattern for files (default: **/*.py for recursive)
        verbose: Print progress
        max_paths: Maximum paths per function
        timeout: Timeout per file
        workers: Number of worker processes (default: CPU count)
    Returns:
        List of ScanResult for each file
    """
    dir_path = Path(dir_path)
    results = []
    files = list(dir_path.glob(pattern))
    workers_count = workers or (os.cpu_count() or 1)
    if workers == 1:
        if verbose:
            print(f"Scanning {len(files)} files in {dir_path} sequentially...")
        for i, file_path in enumerate(sorted(files), 1):
            if verbose:
                print(f"[{i}/{len(files)}] {file_path.name}...", end=" ", flush=True)
            try:
                result = scan_file(
                    file_path,
                    verbose=False,
                    max_paths=max_paths,
                    timeout=timeout,
                    auto_tune=auto_tune,
                )
                results.append(result)
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
            total_issues = sum(len(r.issues) for r in results)
            files_with_issues = sum(1 for r in results if r.issues)
            print(f"\\nSummary: {total_issues} issues in {files_with_issues}/{len(results)} files")
        return results
    if verbose:
        print(f"Scanning {len(files)} files in {dir_path} using {workers_count} workers...")
    with concurrent.futures.ProcessPoolExecutor(max_workers=workers_count) as executor:
        future_to_file = {
            executor.submit(
                scan_file,
                file_path=f,
                verbose=False,
                max_paths=max_paths,
                timeout=timeout,
                auto_tune=auto_tune,
            ): f
            for f in files
        }
        completed_count = 0
        for future in concurrent.futures.as_completed(future_to_file):
            file_path = future_to_file[future]
            try:
                result = future.result()
                results.append(result)
                completed_count += 1
                if verbose:
                    status = "✅"
                    if result.error:
                        status = "❌"
                    elif result.issues:
                        status = f"⚠️  {len(result.issues)}"
                    print(f"[{completed_count}/{len(files)}] {file_path.name} {status}")
            except Exception as e:
                print(f"❌ Error scanning {file_path.name}: {e}")
    if verbose:
        total_issues = sum(len(r.issues) for r in results)
        files_with_issues = sum(1 for r in results if r.issues)
        print(f"\\nSummary: {total_issues} issues in {files_with_issues}/{len(results)} files")
    return results


def on_file_event(event):
    """Handle file system events."""
    from pyspectre.core.watch import FileEventType

    if event.event_type in (FileEventType.CREATED, FileEventType.MODIFIED):
        if event.path.suffix == ".py":
            analyze_file(event.path)


def print_final_summary():
    """Print final session summary."""
    global session
    if not session:
        return
    summary = session.get_summary()
    print(f"\\n\\n{'=' * 70}")
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
    print(f"\\n   📁 Log saved to: {session.log_file}")
    print("=" * 70)


def main():
    """CLI entry point for watch mode."""
    global session
    from pyspectre.core.watch import FileWatcher

    parser = argparse.ArgumentParser(description="PySpectre Scanner")
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
        print(f"Scanning {len(existing_files)} Python files in {scan_dir}...\\n")
        for f in sorted(existing_files):
            analyze_file(f)
    else:
        print(f"No Python files found in {scan_dir}")
    if args.watch:
        print(f"\\n╔══════════════════════════════════════════════════════════════════════╗")
        print(f"║                   PySpectre Scanner - Watch Mode                     ║")
        print(f"╠══════════════════════════════════════════════════════════════════════╣")
        print(f"║  Watching: {str(scan_dir):<56} ║")
        print(f"║  Log:      {str(session.log_file):<56} ║")
        print(f"║  Press Ctrl+C to stop and see summary.                               ║")
        print(f"╚══════════════════════════════════════════════════════════════════════╝\\n")
        watcher = FileWatcher(paths=[scan_dir], patterns=["*.py"])
        watcher.on_change(on_file_event)
        watcher.start()
        try:
            print("👁️  Watching for file changes...")
            while True:
                import time

                time.sleep(1)
        except KeyboardInterrupt:
            print("\\n\\nStopping watcher...")
            watcher.stop()
    print_final_summary()
    print("\\nDone.")


if __name__ == "__main__":
    main()
