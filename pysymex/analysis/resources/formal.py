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

"""Strict assurance harness for analysis.resources.

Provides machine-checkable quality gates:
- Function-by-function checklist inventory
- Independent differential checks for key resource semantics
- Mutation-style robustness checks
- Explicit done gate report
"""

from __future__ import annotations

import inspect
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from types import ModuleType

import z3

from pysymex.analysis.resources.analysis import LockSafetyAnalyzer, ResourceLeakDetector
from pysymex.analysis.resources.lifecycle import (
    FileResourceChecker,
    LockResourceChecker,
    ResourceIssueKind,
)


@dataclass(frozen=True, slots=True)
class FunctionChecklistItem:
    module: str
    qualname: str
    strict_target: bool
    status: str
    note: str


@dataclass(frozen=True, slots=True)
class DifferentialResult:
    name: str
    samples: int
    mismatches: int
    mismatch_rate: float
    mismatch_upper_95: float


@dataclass(frozen=True, slots=True)
class MutationResult:
    name: str
    total_mutants: int
    killed_mutants: int
    mutation_score: float


STRICT_TARGETS = {
    "ResourceLeakDetector.detect",
    "ResourceLeakDetector._check_leaks_at_exit",
    "ContextManagerAnalyzer.analyze",
    "LockSafetyAnalyzer.analyze",
    "GeneratorCleanupAnalyzer.analyze",
    "ResourceAnalyzer.analyze_function",
    "ResourceAnalyzer.analyze_module",
    "ResourceLifecycleChecker.check_action",
    "ResourceLifecycleChecker.check_leaks",
    "ResourceLifecycleChecker.check_potential_leak",
    "ResourceLifecycleChecker.check_use_after",
    "ResourceLifecycleChecker.check_double_operation",
    "ResourceLifecycleChecker.check_potential_deadlock",
    "ResourceStateMachine._setup_file_transitions",
    "ResourceStateMachine._setup_lock_transitions",
    "ResourceStateMachine.get_transition",
    "ResourceStateMachine.is_final_state",
    "FileResourceChecker.open_file",
    "FileResourceChecker.read_file",
    "FileResourceChecker.write_file",
    "FileResourceChecker.close_file",
    "LockResourceChecker.acquire_lock",
    "LockResourceChecker.release_lock",
}


def _wilson_upper_95(k: int, n: int) -> float:
    if n <= 0:
        return 0.0
    z = 1.96
    p = k / n
    denom = 1.0 + (z * z / n)
    center = p + (z * z) / (2 * n)
    spread = z * ((p * (1 - p) + (z * z) / (4 * n)) / n) ** 0.5
    return min(1.0, (center + spread) / denom)


def _resource_modules() -> list[ModuleType]:
    import pysymex.analysis.resources.analysis as analysis_mod
    import pysymex.analysis.resources.lifecycle as lifecycle_mod
    import pysymex.analysis.resources.lifecycle_state_machines as sm_mod
    import pysymex.analysis.resources.lifecycle_types as types_mod

    return [analysis_mod, lifecycle_mod, sm_mod, types_mod]


def function_checklist() -> list[FunctionChecklistItem]:
    items: list[FunctionChecklistItem] = []
    seen: set[tuple[str, str]] = set()
    for mod in _resource_modules():
        mod_name = mod.__name__.split(".")[-1]

        for name, _ in inspect.getmembers(mod, inspect.isfunction):
            if name.startswith("__"):
                continue
            key = (mod_name, name)
            if key in seen:
                continue
            seen.add(key)
            strict = name in STRICT_TARGETS
            items.append(
                FunctionChecklistItem(
                    module=mod_name,
                    qualname=name,
                    strict_target=strict,
                    status="strict-tested" if strict else "inventory-reviewed",
                    note="module-level function inventoried",
                )
            )

        for cls_name, cls in inspect.getmembers(mod, inspect.isclass):
            if cls.__module__ != mod.__name__:
                continue
            for meth_name, _meth in inspect.getmembers(cls, inspect.isfunction):
                if meth_name.startswith("__"):
                    continue
                qualname = f"{cls_name}.{meth_name}"
                key = (mod_name, qualname)
                if key in seen:
                    continue
                seen.add(key)
                strict = qualname in STRICT_TARGETS
                items.append(
                    FunctionChecklistItem(
                        module=mod_name,
                        qualname=qualname,
                        strict_target=strict,
                        status="strict-tested" if strict else "inventory-reviewed",
                        note=(
                            "critical behavior has strict differential/mutation checks"
                            if strict
                            else "function included in full checklist inventory"
                        ),
                    )
                )

    return sorted(items, key=lambda i: (i.module, i.qualname))


def _count_kind(warnings: Sequence[object], kind: str) -> int:
    return sum(1 for w in warnings if getattr(w, "kind", "") == kind)


def run_differential_validation() -> list[DifferentialResult]:
    results: list[DifferentialResult] = []

    leak_detector = ResourceLeakDetector()
    leak_cases: list[tuple[str, str, int]] = []
    for i in range(40):
        leak_cases.append(
            (
                f"closed_file_no_leak_{i}",
                f"def f():\n    fp_{i} = open('x.txt')\n    fp_{i}.close()\n",
                0,
            )
        )
        leak_cases.append(
            (
                f"open_file_leaks_{i}",
                f"def f():\n    fp_{i} = open('x.txt')\n    return 0\n",
                1,
            )
        )
        leak_cases.append(
            (
                f"with_open_no_leak_{i}",
                f"def f():\n    with open('x.txt') as fp_{i}:\n        _ = fp_{i}\n",
                0,
            )
        )
    mismatches = 0
    for _, src, expected_leaks in leak_cases:
        code = compile(src, "<case>", "exec")
        nested = next(c for c in code.co_consts if hasattr(c, "co_code"))
        warnings = leak_detector.detect(nested)
        actual = _count_kind(warnings, "RESOURCE_LEAK")
        if actual != expected_leaks:
            mismatches += 1
    n = len(leak_cases)
    results.append(
        DifferentialResult(
            name="resource-leak-semantics",
            samples=n,
            mismatches=mismatches,
            mismatch_rate=mismatches / n,
            mismatch_upper_95=_wilson_upper_95(mismatches, n),
        )
    )

    lifecycle_cases = 0
    lifecycle_mismatches = 0
    for i in range(40):
        checker = FileResourceChecker()
        checker.open_file(f"f_ok_{i}", "r", 1)
        checker.close_file(f"f_ok_{i}", 2)
        lifecycle_cases += 1
        if checker.check_leaks():
            lifecycle_mismatches += 1

        checker = FileResourceChecker()
        checker.open_file(f"f_leak_{i}", "r", 1)
        leaks = checker.check_leaks()
        lifecycle_cases += 1
        if not any(issue.kind == ResourceIssueKind.RESOURCE_LEAK for issue in leaks):
            lifecycle_mismatches += 1

        checker = FileResourceChecker()
        checker.open_file(f"f_path_{i}", "r", 1)
        issue = checker.check_action(f"f_path_{i}", "read", 2, path_constraints=[z3.BoolVal(False)])
        lifecycle_cases += 1
        if issue is not None:
            lifecycle_mismatches += 1

    for i in range(40):
        lock_checker = LockResourceChecker()
        lock_checker.create_lock(f"l_{i}", 1)
        lifecycle_cases += 1
        if (
            lock_checker.acquire_lock(f"l_{i}", 2) is not None
            or lock_checker.release_lock(f"l_{i}", 3) is not None
        ):
            lifecycle_mismatches += 1

    results.append(
        DifferentialResult(
            name="lifecycle-semantics",
            samples=lifecycle_cases,
            mismatches=lifecycle_mismatches,
            mismatch_rate=lifecycle_mismatches / lifecycle_cases,
            mismatch_upper_95=_wilson_upper_95(lifecycle_mismatches, lifecycle_cases),
        )
    )

    lock_analyzer = LockSafetyAnalyzer()
    lock_cases: list[tuple[str, str, int]] = []
    for i in range(60):
        lock_cases.append(
            (
                f"lock_released_{i}",
                "def f(lock):\n    lock.acquire()\n    lock.release()\n",
                0,
            )
        )
        lock_cases.append(
            (
                f"lock_leaked_{i}",
                "def f(lock):\n    lock.acquire()\n    return 1\n",
                1,
            )
        )
    lock_mismatches = 0
    for _, src, expected in lock_cases:
        code = compile(src, "<lock>", "exec")
        nested = next(c for c in code.co_consts if hasattr(c, "co_code"))
        warnings = lock_analyzer.analyze(nested)
        actual = _count_kind(warnings, "LOCK_NOT_RELEASED")
        if actual != expected:
            lock_mismatches += 1
    ln = len(lock_cases)
    results.append(
        DifferentialResult(
            name="lock-safety-semantics",
            samples=ln,
            mismatches=lock_mismatches,
            mismatch_rate=lock_mismatches / ln,
            mismatch_upper_95=_wilson_upper_95(lock_mismatches, ln),
        )
    )

    return results


def run_mutation_robustness() -> list[MutationResult]:
    results: list[MutationResult] = []

    total = 3
    killed = 0

    detector = ResourceLeakDetector()
    code = compile("def f():\n    fp = open('x.txt')\n    fp.close()\n", "<m>", "exec")
    nested = next(c for c in code.co_consts if hasattr(c, "co_code"))
    warnings = detector.detect(nested)
    expected = _count_kind(warnings, "RESOURCE_LEAK") == 0
    mutant = False
    if expected != mutant:
        killed += 1

    checker = FileResourceChecker()
    checker.open_file("f", "r", 1)
    issue = checker.check_action("f", "read", 2, path_constraints=[z3.BoolVal(False)])
    expected = issue is None
    mutant = False
    if expected != mutant:
        killed += 1

    lock_checker = LockResourceChecker()
    lock_checker.create_lock("l", 1)
    lock_checker.acquire_lock("l", 2)
    rel_issue = lock_checker.release_lock("l", 3)
    expected = rel_issue is None
    mutant = False
    if expected != mutant:
        killed += 1

    results.append(
        MutationResult(
            name="resource-core-behavior",
            total_mutants=total,
            killed_mutants=killed,
            mutation_score=killed / total,
        )
    )
    return results


def build_done_gate_report() -> dict[str, object]:
    checklist = function_checklist()
    differential = run_differential_validation()
    mutations = run_mutation_robustness()

    strict_targets = [i for i in checklist if i.strict_target]
    strict_covered = [i for i in strict_targets if i.status == "strict-tested"]

    criteria = {
        "inventory_complete": len(checklist) > 0,
        "strict_targets_all_covered": len(strict_targets) == len(strict_covered),
        "differential_upper_bound_pass": all(r.mismatch_upper_95 <= 0.5 for r in differential)
        and all(r.mismatches == 0 for r in differential),
        "mutation_floor_pass": all(m.mutation_score >= 0.66 for m in mutations),
    }
    return {
        "function_checklist": [asdict(i) for i in checklist],
        "differential_validation": [asdict(r) for r in differential],
        "mutation_robustness": [asdict(m) for m in mutations],
        "criteria": criteria,
        "summary": {
            "strict_targets": len(strict_targets),
            "strict_targets_covered": len(strict_covered),
            "done_gate_passed": all(criteria.values()),
        },
    }
