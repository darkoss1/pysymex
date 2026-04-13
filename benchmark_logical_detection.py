from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum

import z3

from pysymex.analysis.detectors.logical import create_logic_detector
from pysymex.analysis.detectors.logical.base import (
    ContradictionContext,
    LogicRule,
    LogicalContradictionDetector,
)


class Difficulty(str, Enum):
    EASY = "Easy"
    MEDIUM = "Medium"
    HARD = "Hard"
    EXTREME = "Extreme"
    IMPOSSIBLE = "Impossible"


@dataclass(frozen=True)
class BenchmarkCase:
    name: str
    difficulty: Difficulty
    expected_rule: str
    core: list[z3.BoolRef]
    requires_unsat: bool = True


@dataclass(frozen=True)
class CaseResult:
    case: BenchmarkCase
    matched_rule: str | None
    expected_rule_hit: bool
    mathematically_unsat: bool
    elapsed_ms: float


@dataclass(frozen=True)
class Summary:
    total: int
    expected_rule_hits: int
    first_match_hits: int
    mathematically_unsat_hits: int
    avg_elapsed_ms: float


def build_cases() -> list[BenchmarkCase]:
    x, y, z = z3.Ints("x y z")
    loop_i = z3.Int("loop_i")
    n = z3.Int("n")
    arg_x = z3.Int("arg_x")
    result_val = z3.Int("result_val")
    state_mode = z3.Int("state_mode")
    lock_a, lock_b = z3.Ints("lockA_order lockB_order")
    caller_val, callee_val = z3.Ints("caller_value callee_value")

    ret_is_int = z3.Bool("ret_is_int")
    ret_is_str = z3.Bool("ret_is_str")
    api_contract_ok = z3.Bool("api_contract_ok")
    taint_user_input = z3.Bool("taint_user_input")
    resource_open = z3.Bool("resource_open")

    return [
        BenchmarkCase("t1-range", Difficulty.EASY, "Range Contradiction", [x > 10, x < 5]),
        BenchmarkCase("t1-range-tight", Difficulty.EASY, "Range Contradiction", [x >= 7, x <= 6]),
        BenchmarkCase("t1-parity", Difficulty.EASY, "Parity Contradiction", [x % 2 == 0, x % 2 == 1]),
        BenchmarkCase("t1-parity-alt", Difficulty.MEDIUM, "Parity Contradiction", [x % 2 == 1, x % 2 == 0]),
        BenchmarkCase("t1-modular", Difficulty.EASY, "Modular Contradiction", [x % 3 == 0, x % 3 == 1]),
        BenchmarkCase("t1-modular-alt", Difficulty.MEDIUM, "Modular Contradiction", [x % 5 == 2, x % 5 == 4, x % 5 == 1]),
        BenchmarkCase("t1-self", Difficulty.EASY, "Self-Contradiction", [z3.Not(x == x)]),
        BenchmarkCase("t1-arithmetic", Difficulty.MEDIUM, "Arithmetic Impossibility", [x + x == 1, x == 0]),
        BenchmarkCase("t1-arithmetic-alt", Difficulty.HARD, "Arithmetic Impossibility", [x + x == 3, x == 1]),
        BenchmarkCase("t1-equality", Difficulty.EASY, "Equality Contradiction", [x == 1, x == 2]),
        BenchmarkCase("t1-equality-alt", Difficulty.MEDIUM, "Equality Contradiction", [x == 9, x == 10]),
        BenchmarkCase("t1-complement", Difficulty.MEDIUM, "Complement Contradiction", [x > 3, z3.Not(x > 3)]),
        BenchmarkCase("t1-complement-alt", Difficulty.MEDIUM, "Complement Contradiction", [z3.Not(x <= 1), x <= 1]),
        BenchmarkCase("t2-antisymmetry", Difficulty.MEDIUM, "Antisymmetry Violation", [x > y, y >= x]),
        BenchmarkCase("t2-antisymmetry-alt", Difficulty.HARD, "Antisymmetry Violation", [x < y, y <= x]),
        BenchmarkCase("t2-triangle", Difficulty.HARD, "Triangle Impossibility", [x > y, y > z, z >= x]),
        BenchmarkCase("t2-triangle-alt", Difficulty.HARD, "Triangle Impossibility", [x >= y + 1, y >= z + 1, z >= x]),
        BenchmarkCase("t2-sum", Difficulty.MEDIUM, "Sum Impossibility", [x + y == 3, x > 5, y > 5]),
        BenchmarkCase("t2-sum-alt", Difficulty.HARD, "Sum Impossibility", [x + y == 1, x >= 2, y >= 2]),
        BenchmarkCase("t2-product", Difficulty.HARD, "Product Sign Contradiction", [x * y > 0, x > 0, y < 0]),
        BenchmarkCase("t2-product-alt", Difficulty.HARD, "Product Sign Contradiction", [x * y < 0, x >= 0, y >= 0]),
        BenchmarkCase("t2-gcd", Difficulty.HARD, "GCD Impossibility", [x % 2 == 0, x % 2 == 1, y == 0]),
        BenchmarkCase("t2-gcd-alt", Difficulty.HARD, "GCD Impossibility", [x % 3 == 0, y % 3 == 1, x == y]),
        BenchmarkCase("t3-sequential-mod", Difficulty.HARD, "Sequential Modular Contradiction", [(x * 2) % 3 == 0, (x * 2) % 3 == 1]),
        BenchmarkCase("t3-sequential-mod-alt", Difficulty.EXTREME, "Sequential Modular Contradiction", [(x * 5) % 7 == 2, (x * 5) % 7 == 4]),
        BenchmarkCase("t3-post-assignment", Difficulty.HARD, "Post-assignment Contradiction", [x == 4, x > 9]),
        BenchmarkCase("t3-post-assignment-alt", Difficulty.HARD, "Post-assignment Contradiction", [x == 0, x < 0]),
        BenchmarkCase("t3-loop", Difficulty.EXTREME, "Loop Invariant Violation", [loop_i == loop_i + 1]),
        BenchmarkCase("t3-narrowing", Difficulty.HARD, "Narrowing Contradiction", [n >= 0, n <= 10, n > 12]),
        BenchmarkCase("t3-narrowing-alt", Difficulty.HARD, "Narrowing Contradiction", [n >= 1, n <= 3, n > 5]),
        BenchmarkCase("t3-return-type", Difficulty.EXTREME, "Return Type Contradiction", [ret_is_int, ret_is_str, z3.Not(z3.And(ret_is_int, ret_is_str))]),
        BenchmarkCase("t3-return-type-alt", Difficulty.EXTREME, "Return Type Contradiction", [ret_is_int, z3.Not(ret_is_int), ret_is_str]),
        BenchmarkCase("t4-postcondition", Difficulty.EXTREME, "Postcondition Contradiction", [result_val == 1, result_val == 2]),
        BenchmarkCase("t4-postcondition-alt", Difficulty.EXTREME, "Postcondition Contradiction", [result_val == 3, result_val < 0]),
        BenchmarkCase("t4-precondition", Difficulty.EXTREME, "Precondition Impossibility", [arg_x >= 10, arg_x <= 1]),
        BenchmarkCase("t4-precondition-alt", Difficulty.EXTREME, "Precondition Impossibility", [arg_x > 100, arg_x < 0]),
        BenchmarkCase("t4-api-contract", Difficulty.EXTREME, "API Contract Violation", [api_contract_ok, z3.Not(api_contract_ok)]),
        BenchmarkCase("t4-api-contract-alt", Difficulty.EXTREME, "API Contract Violation", [api_contract_ok == z3.BoolVal(True), api_contract_ok == z3.BoolVal(False)]),
        BenchmarkCase("t4-taint", Difficulty.EXTREME, "Taint + Constraint Contradiction", [taint_user_input, z3.Not(taint_user_input)]),
        BenchmarkCase("t4-taint-alt", Difficulty.EXTREME, "Taint + Constraint Contradiction", [taint_user_input == z3.BoolVal(True), taint_user_input == z3.BoolVal(False)]),
        BenchmarkCase(
            "t4-range-propagation",
            Difficulty.EXTREME,
            "Numeric Range Propagation Contradiction",
            [caller_val <= callee_val, callee_val < caller_val],
        ),
        BenchmarkCase(
            "t4-range-propagation-alt",
            Difficulty.IMPOSSIBLE,
            "Numeric Range Propagation Contradiction",
            [caller_val > callee_val, callee_val >= caller_val],
        ),
        BenchmarkCase("t5-state", Difficulty.IMPOSSIBLE, "State Impossibility", [state_mode == 1, state_mode == 2]),
        BenchmarkCase("t5-state-alt", Difficulty.IMPOSSIBLE, "State Impossibility", [state_mode == 7, state_mode == 8]),
        BenchmarkCase("t5-resource", Difficulty.IMPOSSIBLE, "Resource State Contradiction", [resource_open, z3.Not(resource_open)]),
        BenchmarkCase("t5-resource-alt", Difficulty.IMPOSSIBLE, "Resource State Contradiction", [resource_open == z3.BoolVal(True), resource_open == z3.BoolVal(False)]),
        BenchmarkCase("t5-concurrency", Difficulty.IMPOSSIBLE, "Concurrency Contradiction", [lock_a < lock_b, lock_b <= lock_a]),
        BenchmarkCase("t5-concurrency-alt", Difficulty.IMPOSSIBLE, "Concurrency Contradiction", [lock_a > lock_b, lock_b >= lock_a]),
    ]


def evaluate_case(case: BenchmarkCase, rules: list[LogicRule]) -> CaseResult:
    ctx = ContradictionContext(core=case.core, branch_cond=z3.BoolVal(True), path_constraints=[])
    start = time.perf_counter()

    expected_hit = False
    first_match_name: str | None = None

    for rule in sorted(rules, key=lambda r: r.tier):
        if rule.matches(ctx):
            if first_match_name is None:
                first_match_name = rule.name
            if rule.name == case.expected_rule:
                expected_hit = True

    elapsed_ms = (time.perf_counter() - start) * 1000.0
    solver = z3.Solver()
    solver.add(*case.core)
    mathematically_unsat = solver.check() == z3.unsat
    return CaseResult(case, first_match_name, expected_hit, mathematically_unsat, elapsed_ms)


def evaluate_case_selected(case: BenchmarkCase, detector: LogicalContradictionDetector) -> CaseResult:
    ctx = ContradictionContext(core=case.core, branch_cond=z3.BoolVal(True), path_constraints=[])
    start = time.perf_counter()
    selected = detector.select_rule(ctx)
    solver = z3.Solver()
    solver.add(*case.core)
    mathematically_unsat = solver.check() == z3.unsat
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    selected_name = selected.name if selected is not None else None
    expected_hit = selected_name == case.expected_rule
    if case.requires_unsat:
        expected_hit = expected_hit and mathematically_unsat
    return CaseResult(case, selected_name, expected_hit, mathematically_unsat, elapsed_ms)


def summarize(results: list[CaseResult]) -> Summary:
    total = len(results)
    expected_hits = sum(1 for r in results if r.expected_rule_hit)
    first_match_hits = sum(1 for r in results if r.matched_rule == r.case.expected_rule)
    mathematically_unsat_hits = sum(1 for r in results if r.mathematically_unsat == r.case.requires_unsat)
    avg_elapsed_ms = (sum(r.elapsed_ms for r in results) / total) if total else 0.0
    return Summary(total, expected_hits, first_match_hits, mathematically_unsat_hits, avg_elapsed_ms)


def print_report(results: list[CaseResult]) -> None:
    summary = summarize(results)
    print("=== Logical Detector Benchmark (Easy -> Impossible) ===")
    print(f"Cases: {summary.total}")
    print(
        f"Expected-rule hit rate: {summary.expected_rule_hits}/{summary.total} "
        f"({(summary.expected_rule_hits / summary.total * 100.0):.1f}%)"
    )
    print(
        f"First-match precision: {summary.first_match_hits}/{summary.total} "
        f"({(summary.first_match_hits / summary.total * 100.0):.1f}%)"
    )
    print(
        f"Mathematical UNSAT validity: {summary.mathematically_unsat_hits}/{summary.total} "
        f"({(summary.mathematically_unsat_hits / summary.total * 100.0):.1f}%)"
    )
    print(f"Average rule-evaluation time: {summary.avg_elapsed_ms:.3f} ms")

    print("\n-- By Difficulty --")
    for difficulty in Difficulty:
        subset = [r for r in results if r.case.difficulty is difficulty]
        if not subset:
            continue
        s = summarize(subset)
        expected_rate = s.expected_rule_hits / s.total * 100.0
        first_match_rate = s.first_match_hits / s.total * 100.0
        print(
            f"{difficulty.value:<10} | cases={s.total:2d} | expected-hit={expected_rate:6.2f}% "
            f"| first-match={first_match_rate:6.2f}%"
        )

    print("\n-- Case Details --")
    for result in results:
        expected = result.case.expected_rule
        actual = result.matched_rule or "<none>"
        status = "PASS" if result.expected_rule_hit else "FAIL"
        math_status = "UNSAT" if result.mathematically_unsat else "SAT"
        print(
            f"{status:<4} | {result.case.difficulty.value:<10} | {result.case.name:<24} "
            f"| expected={expected:<40} | first={actual:<40} | {math_status:<5} | {result.elapsed_ms:6.3f} ms"
        )


def main() -> int:
    detector = create_logic_detector()
    cases = build_cases()
    results = [evaluate_case_selected(case, detector) for case in cases]
    print_report(results)

    failed = [r for r in results if not r.expected_rule_hit]
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
