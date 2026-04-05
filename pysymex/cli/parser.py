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

"""Argument parser creation for PySyMex CLI."""

from __future__ import annotations

import argparse


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="pysymex",
        description=" PySyMex - Symbolic Execution Engine for Python",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  PySyMex scan path/to/file.py          Scan a file (symbolic mode)
  PySyMex scan path/to/dir -r           Scan directory recursively
  PySyMex scan path/ --mode static      Static analysis mode
  PySyMex scan path/ --mode pipeline    Full pipeline mode
  PySyMex analyze file.py -f func_name  Analyze specific function
  PySyMex verify file.py                Verify function contracts
  PySyMex concolic file.py -f func -n 50  Concolic test generation
  PySyMex benchmark                      Run benchmark suite
        """,
    )

    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as pkg_version

    try:
        __version__ = pkg_version("pysymex")
    except PackageNotFoundError:
        __version__ = "0.1.0a3"

    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--generate-completion",
        choices=["bash", "zsh", "fish"],
        help="Generate shell completion script",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="command")

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan file or directory",
        description="Scan Python code for bugs and vulnerabilities",
    )
    scan_parser.add_argument("path", help="File or directory to scan")
    scan_parser.add_argument(
        "--mode",
        choices=["symbolic", "static", "pipeline"],
        default="symbolic",
        help="Analysis mode (default: symbolic)",
    )
    scan_parser.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (default: text)",
    )
    scan_parser.add_argument(
        "-o",
        "--output",
        help="Write report to file",
    )
    scan_parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Scan directories recursively",
    )
    scan_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )
    scan_parser.add_argument(
        "--max-paths",
        type=int,
        default=200,
        help="Maximum paths to explore (default: 200)",
    )
    scan_parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout per function in seconds (default: 30)",
    )
    scan_parser.add_argument(
        "--workers",
        type=int,
        default=0,
        help=(
            "Number of parallel worker processes. "
            "0 = conservative auto mode (caps to avoid memory spikes). "
            "1 = sequential (no subprocess overhead)."
        ),
    )
    scan_parser.add_argument(
        "--watch",
        action="store_true",
        help="Watch for file changes and re-scan",
    )
    scan_parser.add_argument(
        "--auto",
        action="store_true",
        help="Auto-tune analysis configuration",
    )
    scan_parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable all caching (instruction, result, solver) for fresh analysis",
    )
    scan_parser.add_argument(
        "--max-iterations",
        type=int,
        default=0,
        help="Maximum total iterations per function (0 = auto-calculate)",
    )
    scan_parser.add_argument(
        "--reproduce",
        action="store_true",
        help="Generate reproduction scripts for findings",
    )
    scan_parser.add_argument(
        "--visualize",
        action="store_true",
        help="Show real-time progress visualization",
    )
    scan_parser.add_argument(
        "--async",
        dest="use_async",
        action="store_true",
        help="Use async scanner with TaskGroup-based structured concurrency",
    )
    scan_parser.add_argument(
        "--trace",
        action="store_true",
        help="Emit execution traces for symbolic scan runs",
    )
    scan_parser.add_argument(
        "--trace-output-dir",
        default=".pysymex/traces",
        help="Directory where trace JSONL files are written (default: .pysymex/traces)",
    )
    scan_parser.add_argument(
        "--trace-verbosity",
        choices=["quiet", "delta_only", "full"],
        default="delta_only",
        help="Trace detail level (default: delta_only)",
    )
    scan_parser.add_argument(
        "--sandbox",
        dest="sandbox",
        action="store_true",
        help="Compile scan targets through sandbox bridge (default)",
    )
    scan_parser.add_argument(
        "--no-sandbox",
        dest="sandbox",
        action="store_false",
        help="Disable sandboxed compilation for scan targets",
    )
    scan_parser.set_defaults(sandbox=True)
    scan_parser.add_argument(
        "--deterministic",
        action="store_true",
        help="Use deterministic non-dynamic exploration for reproducible runs",
    )
    scan_parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for deterministic runs (default: 42)",
    )

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze specific function",
        description="Perform symbolic execution on a specific function",
    )
    analyze_parser.add_argument("file", help="Python file to analyze")
    analyze_parser.add_argument(
        "-f",
        "--function",
        required=True,
        help="Function to analyze",
    )
    analyze_parser.add_argument(
        "--args",
        nargs="*",
        help="Symbolic arguments (name:type)",
    )
    analyze_parser.add_argument(
        "--format",
        choices=["text", "json", "sarif", "html", "markdown"],
        default="text",
        help="Output format (default: text)",
    )
    analyze_parser.add_argument(
        "-o",
        "--output",
        help="Write report to file",
    )
    analyze_parser.add_argument(
        "--max-paths",
        type=int,
        default=100000,
        help="Maximum execution paths to explore (default: unlimited with CHTD)",
    )
    analyze_parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Maximum analysis time in seconds (default: 60)",
    )
    analyze_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )

    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify function contracts",
        description="Verify function pre/postconditions and invariants",
    )
    verify_parser.add_argument("file", help="Python file with contracts")
    verify_parser.add_argument(
        "-f",
        "--function",
        help="Specific function to verify (default: all with contracts)",
    )
    verify_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )
    verify_parser.add_argument(
        "--sandbox",
        dest="sandbox",
        action="store_true",
        help="Execute target loading through sandbox bridge (default)",
    )
    verify_parser.add_argument(
        "--no-sandbox",
        dest="sandbox",
        action="store_false",
        help="Disable sandboxed target loading (trusted code only)",
    )
    verify_parser.set_defaults(sandbox=True)

    concolic_parser = subparsers.add_parser(
        "concolic",
        help="Concolic test generation",
        description="Generate test inputs using concolic execution",
    )
    concolic_parser.add_argument("file", help="Python file")
    concolic_parser.add_argument(
        "-f",
        "--function",
        required=True,
        help="Function to test",
    )
    concolic_parser.add_argument(
        "-n",
        "--iterations",
        type=int,
        default=100,
        help="Maximum iterations (default: 100)",
    )
    concolic_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )
    concolic_parser.add_argument(
        "--sandbox",
        dest="sandbox",
        action="store_true",
        help="Execute target loading through sandbox bridge (default)",
    )
    concolic_parser.add_argument(
        "--no-sandbox",
        dest="sandbox",
        action="store_false",
        help="Disable sandboxed target loading (trusted code only)",
    )
    concolic_parser.set_defaults(sandbox=True)

    bench_parser = subparsers.add_parser(
        "benchmark",
        help="Run benchmark suite",
        description="Run performance benchmarks",
    )
    bench_parser.add_argument(
        "--format",
        choices=["text", "json", "html", "markdown", "sarif"],
        default="text",
        help="Output format (default: text)",
    )
    bench_parser.add_argument(
        "-o",
        "--output",
        help="Write results to file",
    )
    bench_parser.add_argument(
        "--baseline",
        help="Compare against baseline file",
    )
    bench_parser.add_argument(
        "-n",
        "--iterations",
        type=int,
        default=5,
        help="Iterations per benchmark (default: 5)",
    )

    check_parser = subparsers.add_parser(
        "check",
        help="Run CI-friendly check (exit code reflects severity)",
        description="Run PySyMex analysis suitable for CI/CD pipelines",
    )
    check_parser.add_argument(
        "paths",
        nargs="+",
        help="Python files or directories to check",
    )
    check_parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default="high",
        help="Minimum severity to cause a non-zero exit (default: high)",
    )
    check_parser.add_argument(
        "--sarif",
        type=str,
        help="Path to write SARIF report",
    )
    check_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )

    return parser
