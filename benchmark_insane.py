"""Insane benchmark: speed, CHTD behavior, and detection fidelity in one run.

This benchmark is intentionally strict on true-positive recall for real bugs,
while still reporting false-positive pressure on clean workloads.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import subprocess
from statistics import mean
import tempfile
from time import perf_counter
from typing import Callable
import sys

from pysymex.analysis.detectors import IssueKind
from pysymex.api import analyze
from pysymex.execution.types import ExecutionConfig


# -----------------------------
# Stress + bug corpus
# -----------------------------
def bug_division_chain(x: int, y: int, z: int) -> int:
    v = (x * 3 + y) - z
    if v % 5 == 0:
        return 100 // (v - v)
    return v


def bug_index_maze(i: int, j: int) -> int:
    arr = [7, 11, 13, 17]
    k = i + j
    if i > 3 and j > 3:
        return arr[k]
    if i < -4:
        return arr[i]
    return arr[0]


def bug_division_guarded(a: int, b: int) -> int:
    denom = a - b
    if a > 50 and b > 50:
        return (a + b) // (denom - denom)
    return a + b


def clean_branch_grid(a: int, b: int, c: int) -> int:
    total = 0
    for i in range(3):
        if a > i:
            total += i * 2
        else:
            total -= i
    if b > c:
        return total + b - c
    return total + c - b


def clean_nested_thresholds(x: int, y: int, z: int) -> int:
    out = 0
    for i in range(4):
        for j in range(3):
            if x + i > y - j:
                out += z + i - j
            else:
                out -= z - i + j
    return out


def stress_symbolic_mix(a: int, b: int, c: int, d: int) -> int:
    acc = 0
    for i in range(4):
        if (a + i) % 2 == 0:
            acc += b * i
        else:
            acc -= c * (i + 1)
        if d > i:
            acc += d - i
        else:
            acc -= i - d
    return acc


@dataclass(frozen=True)
class Case:
    name: str
    func: Callable[..., object]
    symbolic_args: dict[str, str]
    must_detect: set[IssueKind]
    max_runtime_s: float


CASES: tuple[Case, ...] = (
    Case(
        name="bug_division_chain",
        func=bug_division_chain,
        symbolic_args={"x": "int", "y": "int", "z": "int"},
        must_detect={IssueKind.DIVISION_BY_ZERO},
        max_runtime_s=1.2,
    ),
    Case(
        name="bug_index_maze",
        func=bug_index_maze,
        symbolic_args={"i": "int", "j": "int"},
        must_detect={IssueKind.INDEX_ERROR},
        max_runtime_s=1.2,
    ),
    Case(
        name="bug_division_guarded",
        func=bug_division_guarded,
        symbolic_args={"a": "int", "b": "int"},
        must_detect={IssueKind.DIVISION_BY_ZERO},
        max_runtime_s=1.2,
    ),
    Case(
        name="clean_branch_grid",
        func=clean_branch_grid,
        symbolic_args={"a": "int", "b": "int", "c": "int"},
        must_detect=set(),
        max_runtime_s=0.8,
    ),
    Case(
        name="clean_nested_thresholds",
        func=clean_nested_thresholds,
        symbolic_args={"x": "int", "y": "int", "z": "int"},
        must_detect=set(),
        max_runtime_s=1.1,
    ),
    Case(
        name="stress_symbolic_mix",
        func=stress_symbolic_mix,
        symbolic_args={"a": "int", "b": "int", "c": "int", "d": "int"},
        must_detect=set(),
        max_runtime_s=2.0,
    ),
)


SCAN_TARGET = Path("examples/insane_bugpack.py")
SCAN_REQUIRED_KINDS = {"DIVISION_BY_ZERO", "INDEX_ERROR", "NULL_DEREFERENCE"}


def _config() -> ExecutionConfig:
    return ExecutionConfig(
        max_paths=2200,
        max_depth=280,
        max_iterations=35000,
        max_loop_iterations=10,
        timeout_seconds=15.0,
        enable_chtd=True,
        enable_h_acceleration=True,
        enable_caching=False,
        enable_solver_cache=False,
        deterministic_mode=True,
        random_seed=42,
        collect_coverage=True,
        verbose=False,
    )


def _chtd_snapshot(stats: dict[str, object]) -> str:
    c = stats.get("chtd")
    if not isinstance(c, dict):
        return "chtd=n/a"
    runs = c.get("runs", 0)
    unsat_hits = c.get("unsat_hits", 0)
    validated = c.get("unsat_validations", 0)
    mismatch = c.get("unsat_mismatches", 0)
    unstable = c.get("skipped_unstable", 0)
    no_fork = c.get("skipped_no_fork", 0)
    return (
        "chtd="
        f"runs:{runs} unsat_hits:{unsat_hits} validated_unsat:{validated} "
        f"mismatch:{mismatch} skipped_unstable:{unstable} skipped_no_fork:{no_fork}"
    )


def _run_real_world_scan() -> tuple[bool, str, float]:
    if not SCAN_TARGET.exists():
        return False, f"scan target missing: {SCAN_TARGET}", 0.0

    start = perf_counter()
    with tempfile.NamedTemporaryFile(prefix="pysymex_scan_", suffix=".json", delete=False) as f:
        report_path = Path(f.name)

    cmd = [
        sys.executable,
        "-m",
        "pysymex",
        "scan",
        str(SCAN_TARGET),
        "--deterministic",
        "--seed",
        "42",
        "--no-chtd",
        "--max-paths",
        "80",
        "--timeout",
        "8",
        "--format",
        "json",
        "-o",
        str(report_path),
    ]
    try:
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except Exception as exc:
        return False, f"scan execution failed: {exc}", perf_counter() - start

    elapsed = perf_counter() - start
    if not report_path.exists():
        return False, "scan report was not generated", elapsed

    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"scan report parse failed: {exc}", elapsed
    finally:
        try:
            report_path.unlink(missing_ok=True)
        except Exception:
            pass

    found_kinds: set[str] = set()
    for file_result in data.get("results", []):
        for issue in file_result.get("issues", []):
            kind = issue.get("kind")
            if isinstance(kind, str):
                found_kinds.add(kind)

    missing = sorted(SCAN_REQUIRED_KINDS - found_kinds)
    if missing:
        return (
            False,
            f"scan missing required kinds: {missing}; found={sorted(found_kinds)}",
            elapsed,
        )

    if "RUNTIME_ERROR" in found_kinds:
        return False, "scan produced RUNTIME_ERROR findings; run considered unstable", elapsed

    return (
        True,
        (
            "scan_kinds_ok="
            f"{sorted(found_kinds)} "
            f"exit_code={proc.returncode}"
        ),
        elapsed,
    )


def run(rounds: int = 2) -> int:
    cfg = _config()
    total_start = perf_counter()

    expected_bug_signals = 0
    detected_bug_signals = 0
    false_positives = 0
    hard_failures: list[str] = []
    runtime_samples: list[float] = []

    print("=== INSANE BENCHMARK START ===")
    print(f"rounds={rounds} cases={len(CASES)}")

    scan_ok, scan_msg, scan_time = _run_real_world_scan()
    print(f"real_world_scan {'OK' if scan_ok else 'FAIL'} time={scan_time:.3f}s {scan_msg}")
    if not scan_ok:
        hard_failures.append(scan_msg)

    for r in range(1, rounds + 1):
        print(f"\\n--- round {r}/{rounds} ---")
        for case in CASES:
            t0 = perf_counter()
            result = analyze(case.func, case.symbolic_args, config=cfg)
            dt = perf_counter() - t0
            runtime_samples.append(dt)

            found_kinds = {issue.kind for issue in result.issues}
            missing = case.must_detect - found_kinds
            extras = found_kinds - case.must_detect

            expected_bug_signals += len(case.must_detect)
            detected_bug_signals += len(case.must_detect & found_kinds)

            if not case.must_detect:
                false_positives += len(found_kinds)

            status = "OK"
            if missing:
                status = "MISS"
                hard_failures.append(
                    f"{case.name}: missing expected issues {[k.name for k in sorted(missing, key=lambda x: x.name)]}"
                )
            if dt > case.max_runtime_s:
                status = "SLOW"
                hard_failures.append(
                    f"{case.name}: runtime {dt:.3f}s > limit {case.max_runtime_s:.3f}s"
                )

            print(
                f"{case.name:24s} {status:4s} "
                f"time={dt:.3f}s paths={result.paths_explored:4d} issues={len(result.issues):2d} "
                f"missing={len(missing):1d} extras={len(extras):1d} {_chtd_snapshot(result.solver_stats)}"
            )

    total_time = perf_counter() - total_start
    recall = (
        detected_bug_signals / expected_bug_signals if expected_bug_signals > 0 else 1.0
    )
    avg_runtime = mean(runtime_samples) if runtime_samples else 0.0

    print("\\n=== INSANE BENCHMARK SUMMARY ===")
    print(f"total_time={total_time:.3f}s avg_case_time={avg_runtime:.3f}s")
    print(
        f"real_bug_recall={recall * 100:.1f}% "
        f"({detected_bug_signals}/{expected_bug_signals})"
    )
    print(f"false_positives_on_clean={false_positives}")

    # Hard correctness gate: real bugs must always be detected.
    if recall < 1.0:
        hard_failures.append("real_bug_recall below 100%")

    if hard_failures:
        print("\\nFAILURES:")
        for msg in hard_failures:
            print(f"- {msg}")
        return 1

    print("\\nPASS: speed and real-bug detection targets satisfied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(run(rounds=2))
