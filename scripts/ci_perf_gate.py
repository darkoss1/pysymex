#!/usr/bin/env python3
"""CI Performance Regression Gate for pysymex.

Runs the full benchmark suite and compares results against a frozen baseline.
Exits with code 1 if any benchmark regresses beyond the threshold.

Usage:
    python scripts/ci_perf_gate.py
    python scripts/ci_perf_gate.py --baseline benchmarks/v0.1.0a0-baseline.json
    python scripts/ci_perf_gate.py --threshold 15  # allow up to 15% slowdown
    python scripts/ci_perf_gate.py --iterations 3   # faster CI run
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="pysymex CI Performance Regression Gate",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path("benchmarks/v0.1.0a0-baseline.json"),
        help="Path to baseline benchmark JSON (default: benchmarks/v0.1.0a0-baseline.json)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=20.0,
        help="Percent slowdown threshold that triggers a failure (default: 20.0)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=3,
        help="Benchmark iterations per workload (default: 3)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write current benchmark results as JSON",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print all benchmark results, not just regressions",
    )
    return parser.parse_args()


def load_baseline(path: Path) -> list[dict]:
    """Load baseline benchmark data from JSON file."""
    if not path.exists():
        print(f"[ERROR] Baseline file not found: {path}", file=sys.stderr)
        print(
            "  Run: python -m pysymex benchmark --format json -o benchmarks/v0.1.0a0-baseline.json",
            file=sys.stderr,
        )
        sys.exit(2)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            print(
                f"[ERROR] Baseline JSON must be a list of benchmark results: {path}",
                file=sys.stderr,
            )
            sys.exit(2)
        return data
    except (json.JSONDecodeError, OSError) as e:
        print(f"[ERROR] Failed to read baseline: {e}", file=sys.stderr)
        sys.exit(2)


def run_current_benchmarks(iterations: int) -> list:
    """Run the built-in benchmark suite and return results."""
    try:
        from pysymex.benchmarks.suite import create_builtin_benchmarks
    except ImportError as e:
        print(f"[ERROR] Could not import pysymex benchmark suite: {e}", file=sys.stderr)
        print("  Make sure pysymex is installed: pip install -e .", file=sys.stderr)
        sys.exit(2)

    print(f"Running benchmark suite ({iterations} iterations each)...")
    suite = create_builtin_benchmarks()
    results = suite.run_all(iterations=iterations)
    print(f"Completed {len(results)} benchmark(s).\n")
    return results


def compare_results(
    baseline_dicts: list[dict],
    current_results: list,
    threshold: float,
    verbose: bool,
) -> tuple[list[dict], bool]:
    """Compare current results to baseline. Returns (comparison_rows, any_regression)."""
    baseline_by_name = {d["name"]: d for d in baseline_dicts}
    rows = []
    any_regression = False

    for result in current_results:
        name = result.name
        if name not in baseline_by_name:
            if verbose:
                print(f"  [NEW ] {name}: no baseline entry, skipping")
            continue

        base = baseline_by_name[name]
        base_mean = base.get("mean_seconds", 0.0)
        curr_mean = result.mean_seconds

        if base_mean > 0:
            change_pct = ((curr_mean - base_mean) / base_mean) * 100
        else:
            change_pct = 0.0

        is_regression = change_pct > threshold

        rows.append(
            {
                "name": name,
                "baseline_ms": base_mean * 1000,
                "current_ms": curr_mean * 1000,
                "change_pct": change_pct,
                "is_regression": is_regression,
            }
        )

        if is_regression:
            any_regression = True

    return rows, any_regression


def print_report(rows: list[dict], threshold: float, verbose: bool) -> None:
    """Print a human-readable regression report."""
    regressions = [r for r in rows if r["is_regression"]]
    improvements = [r for r in rows if r["change_pct"] < -5.0]
    ok = [r for r in rows if not r["is_regression"] and r["change_pct"] >= -5.0]

    print("=" * 70)
    print("pysymex CI Performance Regression Gate")
    print(f"Threshold: >{threshold:.0f}% slowdown triggers failure")
    print("=" * 70)

    if regressions:
        print(f"\n[FAIL] {len(regressions)} REGRESSION(S) DETECTED:\n")
        for r in regressions:
            direction = f"+{r['change_pct']:.1f}% SLOWER"
            print(f"  !! {r['name']}")
            print(
                f"     Baseline: {r['baseline_ms']:.2f} ms  ->  Current: {r['current_ms']:.2f} ms  ({direction})"
            )
    else:
        print("\n[PASS] No regressions detected.\n")

    if improvements and verbose:
        print(f"\n[INFO] {len(improvements)} improvement(s):")
        for r in improvements:
            print(f"  ++ {r['name']}: {abs(r['change_pct']):.1f}% faster")

    if verbose:
        print(f"\n[INFO] {len(ok)} benchmark(s) within threshold:")
        for r in ok:
            sign = "+" if r["change_pct"] >= 0 else ""
            print(f"  ok {r['name']}: {sign}{r['change_pct']:.1f}%")

    print("\n" + "=" * 70)
    print(
        f"Summary: {len(regressions)} regression(s), {len(improvements)} improvement(s), {len(ok)} unchanged"
    )
    print("=" * 70 + "\n")


def main() -> int:
    """Main entry point. Returns exit code."""
    args = parse_args()

    # Ensure Z3 is available
    try:
        from pysymex._deps import ensure_z3_ready

        ensure_z3_ready()
    except ImportError:
        pass  # Older version without _deps, continue

    baseline_dicts = load_baseline(args.baseline)
    current_results = run_current_benchmarks(args.iterations)

    # Optionally save current results
    if args.output:
        from pysymex.benchmarks.suite import BenchmarkReporter

        BenchmarkReporter.to_json_file(current_results, args.output)
        print(f"Current results saved to: {args.output}")

    rows, any_regression = compare_results(
        baseline_dicts, current_results, args.threshold, args.verbose
    )
    print_report(rows, args.threshold, args.verbose)

    if any_regression:
        print("[EXIT 1] Performance regression(s) found. Fix before merging.", file=sys.stderr)
        return 1

    print("[EXIT 0] All benchmarks within acceptable range.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
