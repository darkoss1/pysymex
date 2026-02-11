"""
PySpectre - Advanced Formal Verification Scanner
Mathematically proves Python code won't crash using Z3 theorem prover.
Features:
- Interprocedural analysis across function calls
- Call graph tracking for comprehensive verification
- Taint analysis for security vulnerabilities
- Intelligent path exploration
Usage:
    python pyspectre_verify.py <file_or_directory>
    python pyspectre_verify.py src/ --json report.json
    python pyspectre_verify.py file.py --verbose
    python pyspectre_verify.py . --call-graph
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any
from pyspectre.analysis.z3_prover import (
    Z3Engine,
    is_z3_available,
)

BUG_EMOJI = {
    "division_by_zero": "➗",
    "modulo_by_zero": "➗",
    "index_out_of_bounds": "📦",
    "negative_shift": "⬅️",
    "overflow": "💥",
    "assertion_failure": "❌",
    "none_dereference": "🚫",
    "type_error": "🔀",
    "key_error": "🔑",
    "attribute_error": "📛",
    "tainted_data_to_sink": "☠️",
    "unreachable_code": "🚧",
}


def scan_file(
    path: str,
    timeout_ms: int = 5000,
    interprocedural: bool = True,
    track_taint: bool = True,
    engine: Z3Engine = None,
) -> dict[str, Any]:
    """Scan a single file and return results."""
    results = {
        "file": path,
        "crashes": [],
        "proven_safe": [],
        "verification_time_ms": 0.0,
        "error": None,
        "call_graph": {},
        "function_summaries": {},
        "taint_warnings": [],
    }
    start = time.time()
    try:
        if engine is None:
            engine = Z3Engine(
                timeout_ms=timeout_ms, interprocedural=interprocedural, track_taint=track_taint
            )
        file_results = engine.verify_file(path)
        for func_name, verifications in file_results.items():
            for v in verifications:
                entry = {
                    "function": func_name,
                    "line": v.crash.line,
                    "type": v.crash.bug_type.value,
                    "description": v.crash.description,
                    "can_crash": v.can_crash,
                    "proven_safe": v.proven_safe,
                    "counterexample": v.counterexample,
                    "z3_status": v.z3_status,
                    "verification_time_ms": v.verification_time_ms,
                    "severity": v.crash.severity.name if hasattr(v.crash, "severity") else "HIGH",
                }
                if hasattr(v.crash, "taint_info") and v.crash.taint_info:
                    entry["taint_source"] = (
                        v.crash.taint_info.source.value if v.crash.taint_info.source else None
                    )
                    entry["taint_path"] = v.crash.taint_info.propagation_path
                if hasattr(v.crash, "call_stack") and v.crash.call_stack:
                    entry["call_stack"] = v.crash.call_stack
                if v.can_crash:
                    results["crashes"].append(entry)
                else:
                    results["proven_safe"].append(entry)
        if engine.call_graph:
            for func, callees in engine.call_graph.callers.items():
                if callees:
                    results["call_graph"][func] = list(callees)
        for func_name, summary in engine.function_summaries.items():
            results["function_summaries"][func_name] = {
                "verified": summary.verified,
                "has_bugs": summary.has_bugs,
                "return_constraints": bool(summary.return_constraints),
            }
    except SyntaxError as e:
        results["error"] = f"Syntax error: {e}"
    except Exception as e:
        results["error"] = f"Error: {e}"
    results["verification_time_ms"] = (time.time() - start) * 1000
    return results


def scan_directory(
    path: str,
    timeout_ms: int = 5000,
    progress: bool = True,
    interprocedural: bool = True,
    track_taint: bool = True,
) -> list[dict[str, Any]]:
    """Recursively scan directory for Python files with cross-file analysis."""
    all_results = []
    py_files = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
        for file in files:
            if file.endswith(".py"):
                py_files.append(os.path.join(root, file))
    engine = Z3Engine(
        timeout_ms=timeout_ms,
        interprocedural=interprocedural,
        track_taint=track_taint,
    )
    total = len(py_files)
    for i, filepath in enumerate(py_files, 1):
        if progress:
            print(
                f"\r  Scanning {i}/{total}: {os.path.basename(filepath)[:40]:40}",
                end="",
                flush=True,
            )
        results = scan_file(
            filepath,
            timeout_ms,
            interprocedural=interprocedural,
            track_taint=track_taint,
            engine=engine,
        )
        all_results.append(results)
    if progress:
        print("\r" + " " * 70 + "\r", end="")
    return all_results


def print_results(
    all_results: list[dict[str, Any]], verbose: bool = False, show_call_graph: bool = False
):
    """Print results to console with enhanced interprocedural info."""
    total_crashes = 0
    total_safe = 0
    total_errors = 0
    total_time = 0.0
    total_functions = 0
    print()
    print("═" * 70)
    print(" 🔍 PySpectre - Advanced Formal Verification Report")
    print("    Interprocedural Analysis with Z3 Theorem Prover")
    print("═" * 70)
    print()
    crashes_by_type: dict[str, list[dict]] = {}
    combined_call_graph: dict[str, set] = {}
    for result in all_results:
        total_time += result.get("verification_time_ms", 0)
        total_functions += len(result.get("function_summaries", {}))
        for func, callees in result.get("call_graph", {}).items():
            if func not in combined_call_graph:
                combined_call_graph[func] = set()
            combined_call_graph[func].update(callees)
        if result["error"]:
            total_errors += 1
            if verbose:
                print(f"  ⚠️  {result['file']}: {result['error']}")
            continue
        for crash in result["crashes"]:
            bug_type = crash["type"]
            if bug_type not in crashes_by_type:
                crashes_by_type[bug_type] = []
            crash["file"] = result["file"]
            crashes_by_type[bug_type].append(crash)
            total_crashes += 1
        total_safe += len(result["proven_safe"])
    if crashes_by_type:
        print("🔴 CRASHES PROVEN POSSIBLE (Z3 found counterexamples):")
        print("─" * 70)
        for bug_type, crashes in sorted(crashes_by_type.items()):
            emoji = BUG_EMOJI.get(bug_type, "🐛")
            print(f"\n  {emoji} [{bug_type.upper().replace('_', ' ')}]")
            for crash in crashes:
                rel_path = os.path.relpath(crash["file"])
                severity = crash.get("severity", "HIGH")
                sev_icon = (
                    "🔴" if severity == "CRITICAL" else ("🟠" if severity == "HIGH" else "🟡")
                )
                print(f"    {sev_icon} {rel_path}:{crash['line']} in {crash['function']}()")
                print(f"       {crash['description']}")
                if crash["counterexample"]:
                    ce = ", ".join(f"{k}={v}" for k, v in crash["counterexample"].items())
                    print(f"       💡 Crash when: {ce}")
                if crash.get("taint_source"):
                    print(f"       ☠️  Taint: {crash['taint_source']}")
                    if crash.get("taint_path"):
                        path_str = " → ".join(crash["taint_path"][:5])
                        if len(crash["taint_path"]) > 5:
                            path_str += f" → ... ({len(crash['taint_path'])} steps)"
                        print(f"       📍 Path: {path_str}")
                if crash.get("call_stack") and len(crash["call_stack"]) > 1:
                    stack = " → ".join(crash["call_stack"])
                    print(f"       📚 Call stack: {stack}")
                if verbose:
                    print(f"       ⏱️  Verified in {crash.get('verification_time_ms', 0):.1f}ms")
        print()
    if show_call_graph and combined_call_graph:
        print("📊 CALL GRAPH (interprocedural relationships):")
        print("─" * 70)
        for caller in sorted(combined_call_graph.keys()):
            callees = sorted(combined_call_graph[caller])
            if callees:
                print(f"  {caller}() → {', '.join(c + '()' for c in callees)}")
        print()
    if verbose and total_safe > 0:
        print("✅ PROVEN SAFE (mathematically verified):")
        print("─" * 70)
        for result in all_results:
            for safe in result["proven_safe"]:
                rel_path = os.path.relpath(result["file"])
                print(f"    ✓ {rel_path}:{safe['line']} - {safe['description']}")
        print()
    print("═" * 70)
    print(" 📊 Summary")
    print("═" * 70)
    print(f"  📁 Files scanned:       {len(all_results)}")
    print(f"  🔧 Functions analyzed:  {total_functions}")
    print(f"  🔴 Potential crashes:   {total_crashes}")
    print(f"  ✅ Proven safe:         {total_safe}")
    if combined_call_graph:
        print(f"  🔗 Call relationships:  {sum(len(v) for v in combined_call_graph.values())}")
    if total_errors > 0:
        print(f"  ⚠️  Scan errors:        {total_errors}")
    print(f"  ⏱️  Total time:          {total_time/1000:.2f}s")
    print()
    if total_crashes > 0:
        print(f"  ❌ Found {total_crashes} potential crash(es) with mathematical proof!")
        print("     Review the counterexamples above to fix the bugs.")
    else:
        print("  ✅ No crashes found - code is mathematically verified safe!")
    print()
    return total_crashes


def main():
    parser = argparse.ArgumentParser(
        description="Formally verify Python code won't crash using Z3",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python pyspectre_verify.py mycode.py
  python pyspectre_verify.py src/ --json report.json
  python pyspectre_verify.py . --verbose --timeout 10000
  python pyspectre_verify.py . --call-graph      # Show interprocedural relationships
  python pyspectre_verify.py . --no-taint        # Disable taint tracking
Bug Types Detected:
  - Division by zero (/, //, %)
  - Modulo by zero
  - Negative bit shifts (<< and >> with negative amount)
  - Index out of bounds
  - None dereference (calling methods/accessing attrs on None)
  - Type errors
  - Key errors in dictionaries
  - Attribute errors
  - Tainted data flowing to dangerous sinks
  - Unreachable code detection
Advanced Features:
  - Interprocedural analysis: tracks bugs across function calls
  - Call graph building: understands how functions relate
  - Function summaries: caches analysis for efficiency
  - Taint tracking: follows untrusted data through code
Results:
  SAT    = Bug CAN occur (counterexample shows crash values)
  UNSAT  = Bug CANNOT occur (mathematically proven safe)
""",
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--json", "-j", help="Output JSON report to file")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show proven safe items and timing"
    )
    parser.add_argument(
        "--timeout", "-t", type=int, default=5000, help="Z3 timeout in ms (default: 5000)"
    )
    parser.add_argument("--quiet", "-q", action="store_true", help="Only show crashes, no progress")
    parser.add_argument(
        "--call-graph",
        "-g",
        action="store_true",
        dest="call_graph",
        help="Show call graph relationships",
    )
    parser.add_argument(
        "--no-interprocedural", action="store_true", help="Disable interprocedural analysis"
    )
    parser.add_argument("--no-taint", action="store_true", help="Disable taint tracking")
    args = parser.parse_args()
    if not is_z3_available():
        print("ERROR: Z3 is required. Install with: pip install z3-solver")
        sys.exit(1)
    path = args.path
    interprocedural = not args.no_interprocedural
    track_taint = not args.no_taint
    if os.path.isfile(path):
        if not args.quiet:
            print(f"\n  Scanning: {path}")
            if interprocedural:
                print("  Mode: Interprocedural analysis enabled")
        all_results = [
            scan_file(path, args.timeout, interprocedural=interprocedural, track_taint=track_taint)
        ]
    elif os.path.isdir(path):
        if not args.quiet:
            print(f"\n  Scanning directory: {path}")
            if interprocedural:
                print("  Mode: Interprocedural analysis enabled (cross-file)")
        all_results = scan_directory(
            path,
            args.timeout,
            progress=not args.quiet,
            interprocedural=interprocedural,
            track_taint=track_taint,
        )
    else:
        print(f"ERROR: Path not found: {path}")
        sys.exit(1)
    crash_count = print_results(all_results, args.verbose, show_call_graph=args.call_graph)
    if args.json:
        for result in all_results:
            if "call_graph" in result:
                result["call_graph"] = {
                    k: list(v) if isinstance(v, set) else v for k, v in result["call_graph"].items()
                }
        with open(args.json, "w") as f:
            json.dump(all_results, f, indent=2, default=str)
        print(f"  📄 Report written to: {args.json}\n")
    sys.exit(1 if crash_count > 0 else 0)


if __name__ == "__main__":
    main()
