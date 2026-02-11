"""Command-line interface for PySpectre.
Provides two modes:
1. Single function analysis: pyspectre file.py -f function_name
2. Full file/directory scan: pyspectre scan path/to/code
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from pyspectre import __version__
from pyspectre.analysis.concolic import ConcolicExecutor
from pyspectre.analysis.contracts import ContractAnalyzer
from pyspectre.api import analyze_file, scan_static
from pyspectre.reporting.formatters import format_result
from pyspectre.reporting.sarif import generate_sarif


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="pyspectre",
        description=" PySpectre - Symbolic Execution Engine for Python",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan entire file (auto-discover all functions)
  pyspectre scan myfile.py
  # Scan entire directory
  pyspectre scan ./src --recursive
  # Analyze specific function  
  pyspectre analyze myfile.py -f my_function
  # Generate JSON report for AI
  pyspectre scan myfile.py --format json
  # Quick check with limited exploration
  pyspectre scan myfile.py --max-paths 50
For more info: https://github.com/darkoss1/pyspecter
        """,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"PySpectre {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan file(s) for bugs (auto-discovers all functions)",
        description="Automatically scan all functions in a file or directory",
    )
    scan_parser.add_argument(
        "--mode",
        choices=["symbolic", "static"],
        default="static",
        help="Analysis mode: 'static' (fast, enhanced detection) or 'symbolic' (deep execution). Default: static",
    )
    scan_parser.add_argument(
        "path",
        type=str,
        help="Python file or directory to scan",
    )
    scan_parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Recursively scan directories",
    )
    scan_parser.add_argument(
        "--format",
        type=str,
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (default: text)",
    )
    scan_parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Output file path (default: stdout)",
    )
    scan_parser.add_argument(
        "--max-paths",
        type=int,
        default=1000,
        help="Max paths per function (default: 1000)",
    )
    scan_parser.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="Timeout per function in seconds (default: 60)",
    )
    scan_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )
    scan_parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Number of worker processes (default: CPU count)",
    )
    scan_parser.add_argument(
        "--auto",
        action="store_true",
        help="Automatically tune configuration based on code complexity",
    )
    scan_parser.add_argument(
        "--watch",
        action="store_true",
        help="Watch for file changes and re-scan automatically",
    )
    scan_parser.add_argument(
        "--generate-completion",
        type=str,
        choices=["bash", "zsh", "fish"],
        help="Generate shell completion script",
    )
    scan_parser.add_argument(
        "--reproduce",
        action="store_true",
        help="Generate reproduction scripts for detected issues",
    )
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze a specific function",
        description="Run symbolic execution on a specific function",
    )
    analyze_parser.add_argument(
        "file",
        type=str,
        help="Python source file",
    )
    analyze_parser.add_argument(
        "-f",
        "--function",
        type=str,
        required=True,
        help="Function name to analyze",
    )
    analyze_parser.add_argument(
        "--args",
        nargs="*",
        help="Symbolic arguments: name:type (e.g., x:int y:str)",
    )
    analyze_parser.add_argument(
        "--format",
        type=str,
        choices=["text", "json", "html", "markdown", "sarif"],
        default="text",
        help="Output format",
    )
    analyze_parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Output file path",
    )
    analyze_parser.add_argument(
        "--max-paths",
        type=int,
        default=1000,
        help="Maximum paths to explore",
    )
    analyze_parser.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="Timeout in seconds",
    )
    analyze_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )
    parser.add_argument(
        "legacy_file",
        type=str,
        nargs="?",
        help="(Legacy) Python file to analyze",
    )
    parser.add_argument(
        "-f",
        "--function",
        type=str,
        dest="legacy_function",
        help="(Legacy) Function to analyze",
    )
    parser.add_argument(
        "--format",
        type=str,
        choices=["text", "json", "html", "markdown", "sarif"],
        default="text",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
    )
    parser.add_argument(
        "--max-paths",
        type=int,
        default=1000,
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=60.0,
    )
    verify_parser = subparsers.add_parser(
        "verify", help="Verify function contracts (@requires/@ensures)"
    )
    verify_parser.add_argument("file", help="Python file to verify")
    verify_parser.add_argument("-f", "--function", help="Function to verify (all if omitted)")
    verify_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    concolic_parser = subparsers.add_parser(
        "concolic", help="Generate test inputs via concolic execution"
    )
    concolic_parser.add_argument("file", help="Python file to analyze")
    concolic_parser.add_argument("-f", "--function", required=True, help="Function to analyze")
    concolic_parser.add_argument("-i", "--iterations", type=int, default=10, help="Max iterations")
    concolic_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    return parser


def cmd_scan(args) -> int:
    """Execute scan command."""

    path = Path(args.path)
    if not path.exists():
        print(f"❌ Error: Path not found: {path}", file=sys.stderr)
        return 1

    if args.verbose:
        print(f"🔍 Scanning: {path} (mode: {args.mode})")

    start_time = time.time()

    if args.mode == "static":
        return _handle_static_scan(args, start_time)

    return _handle_symbolic_scan(args, path, start_time)


def _handle_static_scan(args, start_time: float) -> int:
    """Handle static analysis mode."""
    issues = scan_static(
        Path(args.path),
        recursive=args.recursive,
        verbose=args.verbose,
        min_confidence=0.7,
        show_suppressed=False,
    )
    total_issues = len(issues)
    duration = time.time() - start_time

    if args.format == "json":
        output_data = {
            "pyspectre_version": __version__,
            "mode": "static",
            "total_issues": total_issues,
            "issues": [i.to_dict() for i in issues],
            "duration": duration,
        }
        output = json.dumps(output_data, indent=2, default=str)
    elif args.format == "sarif":
        _print_static_sarif(issues)
        return 0
    else:
        output = _format_static_text_report(issues, total_issues)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        if args.verbose:
            print(f"📄 Report saved to: {args.output}")
    else:
        print(output)
    return 1 if total_issues > 0 else 0


def _handle_symbolic_scan(args, path: Path, start_time: float) -> int:
    """Handle symbolic analysis mode."""
    from pyspectre.scanner import scan_directory, scan_file

    if path.is_file():
        results = [
            scan_file(path, verbose=args.verbose, max_paths=args.max_paths, timeout=args.timeout)
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
            "pyspectre_version": __version__,
            "mode": "symbolic",
            "files_scanned": len(results),
            "total_issues": total_issues,
            "results": [r.to_dict() for r in results],
            "duration": duration,
        }
        output = json.dumps(output_data, indent=2, default=str)
    elif args.format == "sarif":
        output = _get_symbolic_sarif(results)
    else:
        output = _format_symbolic_text_report(results, total_issues, args.reproduce)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        if args.verbose:
            print(f"📄 Report saved to: {args.output}")
    else:
        print(output)
    return 1 if total_issues > 0 else 0


def _format_static_text_report(issues: list, total: int) -> str:
    """Format text report for static scan."""
    lines = [
        "",
        "╔" + "═" * 58 + "╗",
        "║" + "  🔮 PySpectre Static Scan".center(58) + "║",
        "╚" + "═" * 58 + "╝",
        "",
    ]
    lines.append(f"  🐛 Issues:  {total}")
    lines.append("")

    if total == 0:
        lines.append("  ✅ No issues found!")
    else:
        by_file = defaultdict(list)
        for issue in issues:
            by_file[getattr(issue, "file", "unknown")].append(issue)

        for fpath, file_issues in by_file.items():
            lines.append(f"  ─── {fpath} ───")
            for issue in sorted(file_issues, key=lambda x: x.line):
                icon = {"error": "🔴", "warning": "🟠"}.get(
                    getattr(issue, "severity", "warning"), "🟡"
                )
                lines.append(f"    {icon} [{issue.kind}] Line {issue.line}: {issue.message}")
                if getattr(issue, "suggestion", None):
                    lines.append(f"       💡 {issue.suggestion}")
    lines.extend(["", "─" * 60])
    return "\n".join(lines)


def _format_symbolic_text_report(results: list, total: int, reproduce: bool) -> str:
    """Format text report for symbolic scan."""
    lines = [
        "",
        "╔" + "═" * 58 + "╗",
        "║" + "  🔮 PySpectre Symbolic Scan".center(58) + "║",
        "╚" + "═" * 58 + "╝",
        "",
    ]
    lines.append(f"  📁 Scanned: {len(results)} file(s)")
    lines.append(f"  🐛 Issues:  {total}")
    lines.append("")

    if total == 0:
        lines.append("  ✅ No issues found!")
    else:
        for result in results:
            if not result.issues:
                continue
            lines.append(f"  ─── {result.file_path} ───")
            for issue in result.issues:
                kind = issue.get("kind", "UNKNOWN")
                icon = (
                    "🔴"
                    if kind in ("DIVISION_BY_ZERO", "ASSERTION_ERROR")
                    else "🟠" if kind in ("INDEX_ERROR", "KEY_ERROR") else "🟡"
                )
                lines.append(
                    f"    {icon} [{kind}] Line {issue.get('line_number', '?')}: {issue.get('message', '')}"
                )
                ce = issue.get("counterexample")
                if ce:
                    lines.append(
                        f"       ↳ Trigger: {', '.join(f'{k}={v}' for k, v in ce.items())}"
                    )
            if reproduce:
                _add_reproduction_info(lines, result.issues, result.file_path)
    lines.append("─" * 60)
    return "\n".join(lines)


def _add_reproduction_info(lines, issues, file_path):
    """Add reproduction links to lines."""
    from pyspectre.reporting.reproduction import ReproductionGenerator

    gen = ReproductionGenerator()
    lines.extend(["", "    [!] Reproduction Scripts:"])
    for issue in issues:
        if issue.get("counterexample"):

            class IssueObj:
                def __init__(self, data):
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


def _get_symbolic_sarif(results) -> str:
    """Generate SARIF for symbolic scan."""
    from pyspectre.reporting.sarif import SARIFGenerator

    generator = SARIFGenerator()
    all_issues = []
    all_files = []
    for r in results:
        all_files.append(str(r.file_path))
        for issue in r.issues:
            si = issue.copy()
            si["type"] = issue.get("kind", "UNKNOWN")
            si["file"] = str(r.file_path)
            all_issues.append(si)
    return generator.generate(issues=all_issues, analyzed_files=all_files).to_json()


def cmd_analyze(args) -> int:
    """Execute analyze command for single function."""
    filepath = Path(args.file)
    if not filepath.exists():
        print(f"❌ Error: File not found: {filepath}", file=sys.stderr)
        return 1
    symbolic_args = {}
    if args.args:
        for arg in args.args:
            if ":" in arg:
                name, type_hint = arg.split(":", 1)
                symbolic_args[name.strip()] = type_hint.strip()
    if args.verbose:
        print(f"🔍 Analyzing {args.function}() in {filepath}")
    try:
        result = analyze_file(
            filepath=filepath,
            function_name=args.function,
            symbolic_args=symbolic_args,
            max_paths=args.max_paths,
            timeout=args.timeout,
            verbose=args.verbose,
        )
        output = format_result(result, args.format)
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
            if args.verbose:
                print(f"📄 Report saved to: {args.output}")
        else:
            print(output)
        return 1 if result.has_issues() else 0
    except (ValueError, TypeError, SyntaxError, OSError) as e:
        print(f"❌ Error analyzing {filepath}: {e}", file=sys.stderr)
        return 1


def generate_completion(shell: str) -> int:
    """Generate shell completion script."""
    completions = {
        "bash": """
_pyspectre_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="--version --help scan analyze"
   
    if [[ ${cur} == -* ]]; then
        COMPREPLY=( $(compgen -W "--version --help --format --output --max-paths --timeout --verbose --workers --recursive --watch --auto --reproduce" -- ${cur}) )
        return 0
    fi
   
    if [[ ${prev} == "--format" ]]; then
        COMPREPLY=( $(compgen -W "text json sarif html markdown" -- ${cur}) )
        return 0
    fi
   
    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
    return 0
}
complete -F _pyspectre_completion pyspectre
""",
        "zsh": """
#compdef pyspectre

_pyspectre() {
    local curcontext="$curcontext" state line
    typeset -A opt_args
   
    _arguments -C \\
        '(-v --version)'{-v,--version}'[Show version]' \\
        '(-h --help)'{-h,--help}'[Show help]' \\
        '(--format)--format[Output format]:format:(text json sarif html markdown)' \\
        '(-o --output)'{-o,--output}'[Output file]:file:_files' \\
        '(--max-paths)--max-paths[Max paths to explore]:paths:' \\
        '(--timeout)--timeout[Timeout in seconds]:timeout:' \\
        '(-v --verbose)'{-v,--verbose}'[Verbose output]' \\
        '(-r --recursive)'{-r,--recursive}'[Recursive scan]' \\
        '(--watch)--watch[Watch for changes]' \\
        '1: :->command' \\
        '*:: :->args'
   
    case "$state" in
        command)
            _values 'commands' 'scan' 'analyze'
            ;;
        args)
            case "$line[1]" in
                scan)
                    _files -g "*.py"
                    ;;
                analyze)
                    _files -g "*.py"
                    ;;
            esac
            ;;
    esac
}

_pyspectre "$@"
""",
        "fish": """
# Fish completion for pyspectre

complete -c pyspectre -f

# Options
complete -c pyspectre -s v -l version -d "Show version"
complete -c pyspectre -s h -l help -d "Show help"
complete -c pyspectre -l format -a "text json sarif html markdown" -d "Output format"
complete -c pyspectre -s o -l output -r -d "Output file"
complete -c pyspectre -l max-paths -r -d "Max paths"
complete -c pyspectre -l timeout -r -d "Timeout in seconds"
complete -c pyspectre -s v -l verbose -d "Verbose output"
complete -c pyspectre -s r -l recursive -d "Recursive scan"
complete -c pyspectre -l watch -d "Watch for changes"
complete -c pyspectre -l auto -d "Auto-tune configuration"
complete -c pyspectre -l reproduce -d "Generate reproduction scripts"

# Commands
complete -c pyspectre -n "__fish_use_subcommand" -a "scan" -d "Scan file or directory"
complete -c pyspectre -n "__fish_use_subcommand" -a "analyze" -d "Analyze specific function"

# File completion for scan and analyze
complete -c pyspectre -n "__fish_seen_subcommand_from scan analyze" -a "(__fish_complete_suffix .py)"
""",
    }

    if shell in completions:
        print(completions[shell])
        return 0
    else:
        print(f"Unknown shell: {shell}", file=sys.stderr)
        return 1


def cmd_scan_watch(args) -> int:
    """Execute scan command in watch mode."""
    import time
    from pathlib import Path

    path = Path(args.path)
    if not path.exists():
        print(f"❌ Error: Path not found: {path}", file=sys.stderr)
        return 1

    print(f"👀 Watching {path} for changes... (Press Ctrl+C to stop)")

    file_mtimes: dict[Path, float] = {}

    def get_files_to_watch() -> list[Path]:
        """Get list of Python files to watch."""
        if path.is_file():
            return [path]
        pattern = "**/*.py" if args.recursive else "*.py"
        return list(path.glob(pattern))

    def scan_changed() -> bool:
        """Check if any files have changed."""
        nonlocal file_mtimes
        changed = False
        current_files = get_files_to_watch()

        for file_path in current_files:
            try:
                mtime = file_path.stat().st_mtime
                if file_path not in file_mtimes:
                    file_mtimes[file_path] = mtime
                    changed = True
                    print(f"🆕 New file detected: {file_path}")
                elif file_mtimes[file_path] != mtime:
                    file_mtimes[file_path] = mtime
                    changed = True
                    print(f"📝 File changed: {file_path}")
            except OSError:
                if file_path in file_mtimes:
                    del file_mtimes[file_path]

        for file_path in list(file_mtimes.keys()):
            if file_path not in current_files:
                del file_mtimes[file_path]
                print(f"🗑️  File deleted: {file_path}")

        return changed

    print("\n🔄 Initial scan...")
    cmd_scan(args)

    for file_path in get_files_to_watch():
        try:
            file_mtimes[file_path] = file_path.stat().st_mtime
        except (OSError, FileNotFoundError):
            pass

    try:
        while True:
            time.sleep(1)

            if scan_changed():
                print(f"\n{'=' * 60}")
                print("🔄 Re-scanning due to changes...")
                print(f"{'=' * 60}\n")
                cmd_scan(args)

    except KeyboardInterrupt:
        print("\n👋 Stopping watch mode.")
        return 0


def _print_static_sarif(issues: list[Any]) -> None:
    """Print static analysis results in SARIF format."""
    issue_dicts = [i.to_dict() for i in issues]
    sarif_log = generate_sarif(issues=issue_dicts)
    print(sarif_log.to_json())


def main(argv: list[str] | None = None) -> int:
    """Main entry point."""
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


def cmd_verify(args) -> int:
    """Execute verify command for contracts."""
    filepath = Path(args.file)
    if not filepath.exists():
        print(f"❌ Error: File not found: {filepath}", file=sys.stderr)
        return 1

    try:
        from pyspectre.security import create_sandbox_namespace, get_safe_builtins
        import builtins

        source = filepath.read_text(encoding="utf-8")
        compiled = compile(source, str(filepath), "exec")
        safe_builtins = get_safe_builtins()
        safe_builtins["__import__"] = builtins.__import__
        namespace = create_sandbox_namespace(allow_builtins=False)
        namespace["__builtins__"] = safe_builtins
        namespace["__name__"] = "__main__"
        exec(compiled, namespace)  # nosec B102

        analyzer = ContractAnalyzer()

        if args.function:
            if args.function not in namespace:
                print(f"❌ Error: Function '{args.function}' not found", file=sys.stderr)
                return 1
            func = namespace[args.function]
            report = analyzer.analyze_function(func)
            print(report.format())
            return 1 if report.has_violations else 0
        else:
            has_violations = False
            for obj in namespace.values():
                if callable(obj) and hasattr(obj, "__contract__"):
                    if args.verbose:
                        print(f"🔍 Verifying {obj.__name__}...")
                    report = analyzer.analyze_function(obj)
                    print(report.format())
                    if report.has_violations:
                        has_violations = True
            return 1 if has_violations else 0

    except Exception as e:
        print(f"❌ Error verifying {filepath}: {e}", file=sys.stderr)
        return 1


def cmd_concolic(args) -> int:
    """Execute concolic command for test generation."""
    filepath = Path(args.file)
    if not filepath.exists():
        print(f"❌ Error: File not found: {filepath}", file=sys.stderr)
        return 1

    try:
        from pyspectre.security import create_sandbox_namespace, get_safe_builtins
        import builtins

        source = filepath.read_text(encoding="utf-8")
        compiled = compile(source, str(filepath), "exec")
        safe_builtins = get_safe_builtins()
        safe_builtins["__import__"] = builtins.__import__
        namespace = create_sandbox_namespace(allow_builtins=False)
        namespace["__builtins__"] = safe_builtins
        namespace["__name__"] = "__main__"
        exec(compiled, namespace)  # nosec B102

        if args.function not in namespace:
            print(f"❌ Error: Function '{args.function}' not found", file=sys.stderr)
            return 1
        func = namespace[args.function]

        executor = ConcolicExecutor(max_iterations=args.iterations)
        if args.verbose:
            print(f"🔍 Running concolic execution on {args.function}...")

        result = executor.execute(func)
        print(result.format_summary())

        failing = result.get_failing_inputs()
        if failing:
            print(f"\n❌ Found {len(failing)} failing inputs!")
            return 1
        return 0

    except Exception as e:
        print(f"❌ Error in concolic execution for {filepath}: {e}", file=sys.stderr)
        return 1
