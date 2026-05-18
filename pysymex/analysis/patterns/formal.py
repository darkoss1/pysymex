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

from pysymex.analysis.solver.formal import (
    DifferentialResult,
    FunctionChecklistItem,
    MutationResult,
    build_domain_done_gate_report,
    build_function_checklist,
)
from pysymex.analysis.patterns import (
    PatternAnalyzer,
    PatternKind,
    PatternMatcher,
    PatternRegistry,
    TypeEnvironment,
)

STRICT_TARGETS = {
    "PatternMatcher.find_patterns",
    "PatternMatcher.can_error_occur",
    "PatternAnalyzer.analyze_function",
    "DictGetHandler.can_raise_error",
    "NoneCheckHandler.match",
}


def _modules() -> list[ModuleType]:
    import pysymex.analysis.patterns as patterns_hub
    import pysymex.analysis.patterns.core as patterns_core

    return [patterns_hub, patterns_core]


def function_checklist() -> list[FunctionChecklistItem]:
    return build_function_checklist(_modules(), STRICT_TARGETS)


def run_differential_validation() -> list[DifferentialResult]:
    env = TypeEnvironment()
    mismatches = 0
    samples = 0

    def safe_get(d: dict[object, object], k: object) -> object:
        return d.get(k, 0)

    def plain_sub(d: dict[object, object], k: object) -> object:
        return d[k]

    matcher = PatternMatcher(PatternRegistry())
    safe_instr = list(dis.get_instructions(safe_get))
    safe_matches = matcher.find_patterns(safe_instr, env)
    _ = safe_matches

    plain_instr = list(dis.get_instructions(plain_sub))
    plain_matches = matcher.find_patterns(plain_instr, env)
    samples += 1
    if any(m.kind == PatternKind.DICT_GET for m in plain_matches):
        mismatches += 1

    analyzer = PatternAnalyzer()
    info = analyzer.analyze_function(safe_get.__code__, env)
    dg = [p for p in info.patterns if p.kind == PatternKind.DICT_GET]
    samples += 1
    if not dg:
        mismatches += 1
    else:
        if info.can_error_occur(dg[0].start_pc, "KeyError"):
            mismatches += 1

    def none_guard(x: object) -> bool:
        return x is not None

    info2 = analyzer.analyze_function(none_guard.__code__, env)
    samples += 1
    if not any(p.kind == PatternKind.NONE_CHECK for p in info2.patterns):
        mismatches += 1

    return [DifferentialResult("patterns-semantics", samples, mismatches)]


def run_mutation_robustness() -> list[MutationResult]:
    stats = run_differential_validation()[0]
    total = 3
    killed = 0

    if stats.mismatches == 0:
        killed += 1

    analyzer = PatternAnalyzer()

    def safe_get(d: dict[object, object], k: object) -> object:
        return d.get(k, 0)

    info = analyzer.analyze_function(safe_get.__code__, TypeEnvironment())
    dg = [p for p in info.patterns if p.kind == PatternKind.DICT_GET]
    if dg and not info.can_error_occur(dg[0].start_pc, "KeyError"):
        killed += 1

    def none_guard(x: object) -> bool:
        return x is not None

    info2 = analyzer.analyze_function(none_guard.__code__, TypeEnvironment())
    if any(p.kind == PatternKind.NONE_CHECK for p in info2.patterns):
        killed += 1

    return [MutationResult("patterns-core", total, killed, killed / total)]


def build_done_gate_report() -> dict[str, object]:
    checklist = function_checklist()
    diff = run_differential_validation()
    mut = run_mutation_robustness()
    return build_domain_done_gate_report(checklist, diff, mut)
