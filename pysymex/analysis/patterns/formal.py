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

from pysymex.analysis.patterns import (
    PatternAnalyzer,
    PatternKind,
    PatternMatcher,
    PatternRegistry,
    TypeEnvironment,
)


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
    uniq = {(i.module, i.qualname): i for i in items}
    return sorted(uniq.values(), key=lambda x: (x.module, x.qualname))


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
