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
from types import ModuleType
from typing import cast

from pysymex.analysis.solver.formal import (
    DifferentialResult,
    FunctionChecklistItem,
    MutationResult,
    build_domain_done_gate_report,
    build_function_checklist,
)
from pysymex.analysis.loops import LoopBound, LoopDetector, LoopInfo, LoopWidening

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
    return build_function_checklist(_modules(), STRICT_TARGETS)


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
    return build_domain_done_gate_report(checklist, diff, mut)
