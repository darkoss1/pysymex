"""
PySpectre Z3 Analysis CLI
=========================
Command-line interface for Z3-powered analysis modules.
Usage:
    python -m pyspectre.analyze --arithmetic mycode.py
    python -m pyspectre.analyze --bounds mycode.py
    python -m pyspectre.analyze --types mycode.py
    python -m pyspectre.analyze --resources mycode.py
    python -m pyspectre.analyze --concurrency mycode.py
    python -m pyspectre.analyze --all mycode.py
"""

from __future__ import annotations
import argparse
import ast
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import z3
from pyspectre.analysis.arithmetic_safety import (
    ArithmeticIssue,
    ArithmeticSafetyAnalyzer,
    IntegerWidth,
)
from pyspectre.analysis.bounds_checking import (
    BoundsChecker,
    BoundsIssue,
)
from pyspectre.analysis.concurrency import (
    ConcurrencyAnalyzer,
    ConcurrencyIssue,
)
from pyspectre.analysis.resource_lifecycle import (
    ResourceIssue,
    ResourceKind,
    ResourceLifecycleChecker,
)
from pyspectre.analysis.type_constraints import (
    SymbolicType,
    TypeConstraintChecker,
    TypeIssue,
)


@dataclass
class AnalysisResult:
    """Result from running analyzers on a file."""

    file_path: str
    arithmetic_issues: list[ArithmeticIssue] = field(default_factory=list)
    bounds_issues: list[BoundsIssue] = field(default_factory=list)
    type_issues: list[TypeIssue] = field(default_factory=list)
    resource_issues: list[ResourceIssue] = field(default_factory=list)
    concurrency_issues: list[ConcurrencyIssue] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def total_issues(self) -> int:
        return (
            len(self.arithmetic_issues)
            + len(self.bounds_issues)
            + len(self.type_issues)
            + len(self.resource_issues)
            + len(self.concurrency_issues)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file_path,
            "total_issues": self.total_issues,
            "arithmetic_issues": len(self.arithmetic_issues),
            "bounds_issues": len(self.bounds_issues),
            "type_issues": len(self.type_issues),
            "resource_issues": len(self.resource_issues),
            "concurrency_issues": len(self.concurrency_issues),
            "errors": self.errors,
        }


class CodeAnalyzer:
    """
    Analyzes Python source code using Z3-powered modules.
    Extracts patterns from AST and runs appropriate analyses.
    """

    def __init__(
        self,
        run_arithmetic: bool = False,
        run_bounds: bool = False,
        run_types: bool = False,
        run_resources: bool = False,
        run_concurrency: bool = False,
        verbose: bool = False,
    ):
        self.run_arithmetic = run_arithmetic
        self.run_bounds = run_bounds
        self.run_types = run_types
        self.run_resources = run_resources
        self.run_concurrency = run_concurrency
        self.verbose = verbose
        if run_arithmetic:
            self.arithmetic_analyzer = ArithmeticSafetyAnalyzer(
                default_width=IntegerWidth.INT64,
                signed=True,
            )
        if run_bounds:
            self.bounds_checker = BoundsChecker()
        if run_types:
            self.type_checker = TypeConstraintChecker()
        if run_resources:
            self.resource_checker = ResourceLifecycleChecker()
        if run_concurrency:
            self.concurrency_analyzer = ConcurrencyAnalyzer()

    def analyze_file(self, filepath: Path) -> AnalysisResult:
        """Analyze a Python source file."""
        result = AnalysisResult(file_path=str(filepath))
        try:
            source = filepath.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(filepath))
        except SyntaxError as e:
            result.errors.append(f"Syntax error: {e}")
            return result
        except Exception as e:
            result.errors.append(f"Error reading file: {e}")
            return result
        if self.run_arithmetic:
            result.arithmetic_issues = self._analyze_arithmetic(tree)
        if self.run_bounds:
            result.bounds_issues = self._analyze_bounds(tree)
        if self.run_types:
            result.type_issues = self._analyze_types(tree)
        if self.run_resources:
            result.resource_issues = self._analyze_resources(tree)
        if self.run_concurrency:
            result.concurrency_issues = self._analyze_concurrency(tree)
        return result

    def _analyze_arithmetic(self, tree: ast.AST) -> list[ArithmeticIssue]:
        """Analyze arithmetic operations in the AST."""
        issues = []

        def add_issue(result, line):
            """Helper to handle both single issues and lists."""
            if result is None:
                return
            if isinstance(result, list):
                for issue in result:
                    issue.line_number = line
                    issues.append(issue)
            else:
                result.line_number = line
                issues.append(result)

        for node in ast.walk(tree):
            if isinstance(node, ast.BinOp):
                line = getattr(node, "lineno", None)
                a = z3.Int("a")
                b = z3.Int("b")
                if isinstance(node.op, ast.Add):
                    add_issue(self.arithmetic_analyzer.check_addition_overflow(a, b), line)
                elif isinstance(node.op, ast.Sub):
                    add_issue(self.arithmetic_analyzer.check_subtraction_overflow(a, b), line)
                elif isinstance(node.op, ast.Mult):
                    add_issue(self.arithmetic_analyzer.check_multiplication_overflow(a, b), line)
                elif isinstance(node.op, ast.Div) or isinstance(node.op, ast.FloorDiv):
                    add_issue(self.arithmetic_analyzer.check_division_safety(a, b), line)
                elif isinstance(node.op, ast.Mod):
                    add_issue(self.arithmetic_analyzer.check_modulo_safety(a, b), line)
                elif isinstance(node.op, ast.LShift) or isinstance(node.op, ast.RShift):
                    add_issue(self.arithmetic_analyzer.check_shift_safety(a, b), line)
                elif isinstance(node.op, ast.Pow):
                    add_issue(self.arithmetic_analyzer.check_power_safety(a, b), line)
        return issues

    def _analyze_bounds(self, tree: ast.AST) -> list[BoundsIssue]:
        """Analyze array/list indexing operations."""
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Subscript):
                line = getattr(node, "lineno", None)
                index = z3.Int("index")
                length = z3.Int("length")
                array_name = "array"
                if isinstance(node.value, ast.Name):
                    array_name = node.value.id
                node_issues = self.bounds_checker.check_index(index, length, array_name=array_name)
                for issue in node_issues:
                    issue.line_number = line
                issues.extend(node_issues)
        return issues

    def _analyze_types(self, tree: ast.AST) -> list[TypeIssue]:
        """Analyze type annotations and assignments."""
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.AnnAssign):
                line = getattr(node, "lineno", None)
                target_type = self._annotation_to_type(node.annotation)
                if target_type and node.value:
                    value_type = self._infer_type(node.value)
                    if value_type:
                        issue = self.type_checker.check_assignment(target_type, value_type)
                        if issue:
                            issue.line_number = line
                            issues.append(issue)
        return issues

    def _annotation_to_type(self, node: ast.AST) -> SymbolicType | None:
        """Convert AST annotation to SymbolicType."""
        if isinstance(node, ast.Name):
            name = node.id
            if name == "int":
                return SymbolicType.int_type()
            elif name == "float":
                return SymbolicType.float_type()
            elif name == "str":
                return SymbolicType.str_type()
            elif name == "bool":
                return SymbolicType.bool_type()
            elif name == "None":
                return SymbolicType.none_type()
        return None

    def _infer_type(self, node: ast.AST) -> SymbolicType | None:
        """Infer type from AST expression."""
        if isinstance(node, ast.Constant):
            val = node.value
            if isinstance(val, bool):
                return SymbolicType.bool_type()
            elif isinstance(val, int):
                return SymbolicType.int_type()
            elif isinstance(val, float):
                return SymbolicType.float_type()
            elif isinstance(val, str):
                return SymbolicType.str_type()
            elif val is None:
                return SymbolicType.none_type()
        elif isinstance(node, ast.List):
            return SymbolicType.list_of(SymbolicType.any_type())
        elif isinstance(node, ast.Dict):
            return SymbolicType.dict_of(SymbolicType.any_type(), SymbolicType.any_type())
        return None

    def _analyze_resources(self, tree: ast.AST) -> list[ResourceIssue]:
        """Analyze resource lifecycle (files, locks, etc.)."""
        issues = []
        self.resource_checker.reset()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "open":
                    line = getattr(node, "lineno", None)
                    resource_name = f"file_line_{line}"
                    self.resource_checker.create_resource(resource_name, ResourceKind.FILE, line)
                    self.resource_checker.check_action(resource_name, "open_read", line)
            elif isinstance(node, ast.With):
                pass
        issues.extend(self.resource_checker.check_leaks())
        return issues

    def _analyze_concurrency(self, tree: ast.AST) -> list[ConcurrencyIssue]:
        """Analyze concurrency patterns (threads, locks)."""
        issues = []
        self.concurrency_analyzer.reset()
        has_threading = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if "threading" in alias.name or "concurrent" in alias.name:
                        has_threading = True
            if isinstance(node, ast.ImportFrom):
                if node.module and ("threading" in node.module or "concurrent" in node.module):
                    has_threading = True
        if has_threading:
            self.concurrency_analyzer.create_thread("main", is_main=True)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute):
                        if node.func.attr == "Thread":
                            thread_name = f"thread_line_{getattr(node, 'lineno', 0)}"
                            self.concurrency_analyzer.create_thread(thread_name)
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            line = getattr(node, "lineno", None)
                            self.concurrency_analyzer.record_write(
                                "main", target.id, line_number=line
                            )
            issues.extend(self.concurrency_analyzer.detect_data_races())
        return issues


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="pyspectre-analyze",
        description="PySpectre Z3-Powered Analysis - Deep code analysis using SMT solving",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run arithmetic safety analysis
  python -m pyspectre.analyze --arithmetic mycode.py
  # Run bounds checking analysis
  python -m pyspectre.analyze --bounds mycode.py
  # Run all analyses
  python -m pyspectre.analyze --all mycode.py
  # Run multiple specific analyses
  python -m pyspectre.analyze --arithmetic --bounds --types mycode.py
  # Output as JSON
  python -m pyspectre.analyze --all mycode.py --format json
  # Analyze a directory
  python -m pyspectre.analyze --all --dir ./src
For more information, visit: https://github.com/darkoss1/pyspecter
        """,
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="Python source files to analyze",
    )
    parser.add_argument(
        "-d",
        "--dir",
        type=str,
        help="Directory to scan recursively",
    )
    analysis_group = parser.add_argument_group("Analysis Options")
    analysis_group.add_argument(
        "--arithmetic",
        action="store_true",
        help="Run arithmetic safety analysis (overflow, division by zero, etc.)",
    )
    analysis_group.add_argument(
        "--bounds",
        action="store_true",
        help="Run bounds checking analysis (array/buffer access)",
    )
    analysis_group.add_argument(
        "--types",
        action="store_true",
        help="Run type constraint analysis",
    )
    analysis_group.add_argument(
        "--resources",
        action="store_true",
        help="Run resource lifecycle analysis (file/lock leaks)",
    )
    analysis_group.add_argument(
        "--concurrency",
        action="store_true",
        help="Run concurrency analysis (data races, deadlocks)",
    )
    analysis_group.add_argument(
        "--all",
        action="store_true",
        help="Run all analyses",
    )
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "-o",
        "--output",
        type=str,
        help="Output file path (default: stdout)",
    )
    output_group.add_argument(
        "--format",
        type=str,
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    output_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )
    output_group.add_argument(
        "--version",
        action="version",
        version="PySpectre Analyzer 0.3.0a0",
    )
    return parser


def format_results_text(results: list[AnalysisResult]) -> str:
    """Format results as human-readable text."""
    lines = []
    lines.append("=" * 70)
    lines.append("🔬 PySpectre Z3 Analysis Results")
    lines.append("=" * 70)
    lines.append("")
    total_issues = sum(r.total_issues for r in results)
    for result in results:
        lines.append(f"📄 {result.file_path}")
        lines.append("-" * 50)
        if result.errors:
            for error in result.errors:
                lines.append(f"   ❌ Error: {error}")
            lines.append("")
            continue
        if result.total_issues == 0:
            lines.append("   ✅ No issues found")
        else:
            if result.arithmetic_issues:
                lines.append(f"   🔢 Arithmetic Issues ({len(result.arithmetic_issues)}):")
                for issue in result.arithmetic_issues[:5]:
                    lines.append(f"      • {issue.format()}")
                if len(result.arithmetic_issues) > 5:
                    lines.append(f"      ... and {len(result.arithmetic_issues) - 5} more")
            if result.bounds_issues:
                lines.append(f"   📋 Bounds Issues ({len(result.bounds_issues)}):")
                for issue in result.bounds_issues[:5]:
                    lines.append(f"      • {issue.format()}")
                if len(result.bounds_issues) > 5:
                    lines.append(f"      ... and {len(result.bounds_issues) - 5} more")
            if result.type_issues:
                lines.append(f"   🔤 Type Issues ({len(result.type_issues)}):")
                for issue in result.type_issues[:5]:
                    lines.append(f"      • {issue.format()}")
                if len(result.type_issues) > 5:
                    lines.append(f"      ... and {len(result.type_issues) - 5} more")
            if result.resource_issues:
                lines.append(f"   💾 Resource Issues ({len(result.resource_issues)}):")
                for issue in result.resource_issues[:5]:
                    lines.append(f"      • {issue.format()}")
                if len(result.resource_issues) > 5:
                    lines.append(f"      ... and {len(result.resource_issues) - 5} more")
            if result.concurrency_issues:
                lines.append(f"   🔄 Concurrency Issues ({len(result.concurrency_issues)}):")
                for issue in result.concurrency_issues[:5]:
                    lines.append(f"      • {issue.format()}")
                if len(result.concurrency_issues) > 5:
                    lines.append(f"      ... and {len(result.concurrency_issues) - 5} more")
        lines.append("")
    lines.append("=" * 70)
    lines.append(f"📊 Summary: {len(results)} files analyzed, {total_issues} issues found")
    lines.append("=" * 70)
    return "\n".join(lines)


def format_results_json(results: list[AnalysisResult]) -> str:
    """Format results as JSON."""
    data = {
        "files_analyzed": len(results),
        "total_issues": sum(r.total_issues for r in results),
        "results": [r.to_dict() for r in results],
    }
    return json.dumps(data, indent=2)


def main(argv: list[str] | None = None) -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args(argv)
    run_all = args.all
    run_arithmetic = args.arithmetic or run_all
    run_bounds = args.bounds or run_all
    run_types = args.types or run_all
    run_resources = args.resources or run_all
    run_concurrency = args.concurrency or run_all
    if not any([run_arithmetic, run_bounds, run_types, run_resources, run_concurrency]):
        print("Error: No analysis selected. Use --all or specify analyses.", file=sys.stderr)
        print("Try: python -m pyspectre.analyze --help", file=sys.stderr)
        return 1
    files_to_analyze: list[Path] = []
    if args.files:
        for f in args.files:
            path = Path(f)
            if path.exists() and path.suffix == ".py":
                files_to_analyze.append(path)
            else:
                print(f"Warning: Skipping {f} (not found or not a .py file)", file=sys.stderr)
    if args.dir:
        dir_path = Path(args.dir)
        if dir_path.is_dir():
            files_to_analyze.extend(dir_path.rglob("*.py"))
        else:
            print(f"Error: Directory not found: {args.dir}", file=sys.stderr)
            return 1
    if not files_to_analyze:
        print("Error: No Python files to analyze.", file=sys.stderr)
        return 1
    analyzer = CodeAnalyzer(
        run_arithmetic=run_arithmetic,
        run_bounds=run_bounds,
        run_types=run_types,
        run_resources=run_resources,
        run_concurrency=run_concurrency,
        verbose=args.verbose,
    )
    if args.verbose:
        analyses = []
        if run_arithmetic:
            analyses.append("arithmetic")
        if run_bounds:
            analyses.append("bounds")
        if run_types:
            analyses.append("types")
        if run_resources:
            analyses.append("resources")
        if run_concurrency:
            analyses.append("concurrency")
        print(f"Running analyses: {', '.join(analyses)}")
        print(f"Files to analyze: {len(files_to_analyze)}")
        print()
    results: list[AnalysisResult] = []
    for filepath in files_to_analyze:
        if args.verbose:
            print(f"Analyzing {filepath}...")
        result = analyzer.analyze_file(filepath)
        results.append(result)
    if args.format == "json":
        output = format_results_json(results)
    else:
        output = format_results_text(results)
    if args.output:
        output_path = Path(args.output)
        output_path.write_text(output, encoding="utf-8")
        if args.verbose:
            print(f"\nResults written to {output_path}")
    else:
        print(output)
    total_issues = sum(r.total_issues for r in results)
    return 1 if total_issues > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
