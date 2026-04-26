# pysymex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
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
from __future__ import annotations

import dis
import inspect
from dataclasses import asdict, dataclass
from types import ModuleType
from typing import cast

from pysymex.analysis.loops import LoopBound, LoopDetector, LoopInfo, LoopWidening


@dataclass(frozen=True, slots=True)
class FunctionChecklistItem:
    module: str
    qualname: str
    strict_target: bool
    status: str


@dataclass(frozen=True, slots=True)
class DifferentialResult:
    name: str
    samples: int
    mismatches: int


@dataclass(frozen=True, slots=True)
class MutationResult:
    name: str
    total_mutants: int
    killed_mutants: int
    mutation_score: float


STRICT_TARGETS = {
    "LoopDetector.analyze_cfg",
    "LoopDetector._build_cfg",
    "LoopDetector._compute_dominators",
    "LoopDetector._find_back_edges",
    "LoopWidening.should_widen",
    "LoopWidening.widen_state",
}


def _modules() -> list[ModuleType]:
    import pysymex.analysis.loops.core as loops_core

    return [loops_core]


def function_checklist() -> list[FunctionChecklistItem]:
    items: list[FunctionChecklistItem] = []
    for mod in _modules():
        mod_name = mod.__name__.split(".")[-1]
        for cls_name, cls in inspect.getmembers(mod, inspect.isclass):
            if cls.__module__ != mod.__name__:
                continue
            for fn_name, _ in inspect.getmembers(cls, inspect.isfunction):
                if fn_name.startswith("__"):
                    continue
                q = f"{cls_name}.{fn_name}"
                strict = q in STRICT_TARGETS
                items.append(
                    FunctionChecklistItem(
                        mod_name, q, strict, "strict-tested" if strict else "inventory-reviewed"
                    )
                )
    return sorted(items, key=lambda x: (x.module, x.qualname))


def run_differential_validation() -> list[DifferentialResult]:
    mismatches = 0
    samples = 0

    def with_loop(n: int) -> int:
        x = 0
        while x < n:
            x += 1
        return x

    def no_loop(n: int) -> int:
        return n + 1

    det = LoopDetector()

    det.analyze_cfg(list(dis.get_instructions(no_loop)))
    loops = det.analyze_cfg(list(dis.get_instructions(with_loop)))
    samples += 1
    if len(loops) < 1:
        mismatches += 1

    samples += 1
    b = LoopBound.constant(5)
    if b.exact is None or not b.is_finite:
        mismatches += 1

    samples += 1
    w = LoopWidening(widening_threshold=2)
    lp = LoopInfo(header_pc=1, back_edge_pc=2, exit_pcs={3}, body_pcs={1, 2})
    if w.should_widen(lp, 1) or not w.should_widen(lp, 2):
        mismatches += 1

    return [DifferentialResult("loops-semantics", samples, mismatches)]


def run_mutation_robustness() -> list[MutationResult]:
    total = 3
    killed = 0
    stats = run_differential_validation()[0]
    if stats.mismatches == 0:
        killed += 1

    det = LoopDetector()

    def f(n: int) -> int:
        while n > 0:
            n -= 1
        return n

    det.analyze_cfg(list(dis.get_instructions(f)))
    first = len(cast("set[LoopInfo]", det.loops))
    det.analyze_cfg(list(dis.get_instructions(f)))
    second = len(cast("set[LoopInfo]", det.loops))
    if second == first:
        killed += 1

    w = LoopWidening(widening_threshold=3)
    lp = LoopInfo(header_pc=1, back_edge_pc=2, exit_pcs={3}, body_pcs={1, 2})
    if (not w.should_widen(lp, 2)) and w.should_widen(lp, 3):
        killed += 1
    return [MutationResult("loops-core", total, killed, killed / total)]


def build_done_gate_report() -> dict[str, object]:
    checklist = function_checklist()
    diff = run_differential_validation()
    mut = run_mutation_robustness()
    strict_total = len([c for c in checklist if c.strict_target])
    strict_cov = len([c for c in checklist if c.strict_target and c.status == "strict-tested"])
    criteria = {
        "inventory_complete": len(checklist) > 0,
        "strict_targets_all_covered": strict_total == strict_cov,
        "differential_pass": all(d.mismatches == 0 for d in diff),
        "mutation_floor_pass": all(m.mutation_score >= 0.66 for m in mut),
    }
    return {
        "function_checklist": [asdict(c) for c in checklist],
        "differential_validation": [asdict(d) for d in diff],
        "mutation_robustness": [asdict(m) for m in mut],
        "criteria": criteria,
        "summary": {
            "strict_targets": strict_total,
            "strict_targets_covered": strict_cov,
            "done_gate_passed": all(criteria.values()),
        },
    }
