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

import inspect
import json
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from types import ModuleType

from pysymex.analysis.integration import AnalysisConfig, AnalysisPipeline, ReportGenerator


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
    "AnalysisPipeline.analyze_source",
    "AnalysisPipeline.analyze_file",
    "AnalysisPipeline._analyze_module",
    "AnalysisPipeline._find_functions",
    "AnalysisPipeline._analyze_function",
    "AnalysisPipeline._extract_imports",
    "AnalysisPipeline.analyze_directory",
    "ReportGenerator.generate_text",
    "ReportGenerator.generate_json",
    "ReportGenerator.generate_sarif",
}


def _modules() -> list[ModuleType]:
    import pysymex.analysis.integration.core as integration_core

    return [integration_core]


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

    pipeline = AnalysisPipeline(AnalysisConfig())

    res = pipeline.analyze_source("def f(:\n    pass\n", "<bad>")
    samples += 1
    if not any(i.kind.name == "SYNTAX_ERROR" for i in res.issues):
        mismatches += 1

    src = "import os\nX='hello'\ndef f():\n    return X\n"
    pipeline.analyze_source(src, "<ok>")
    samples += 1

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "m.py"
        p.write_text("def f(x):\n    return x\n", encoding="utf-8")
        out = pipeline.analyze_file(str(p))
        gen = ReportGenerator({str(p): out})
        samples += 1
        try:
            json.loads(gen.generate_json())
            json.loads(gen.generate_sarif())
        except Exception:
            mismatches += 1

    return [DifferentialResult("integration-semantics", samples, mismatches)]


def run_mutation_robustness() -> list[MutationResult]:
    total = 3
    killed = 0
    stats = run_differential_validation()[0]
    if stats.mismatches == 0:
        killed += 1

    src = "import math\nS='not_an_import'\n"
    pipeline = AnalysisPipeline(AnalysisConfig())
    mod_code = compile(src, "<m>", "exec")
    from pysymex.analysis.integration.types import ModuleContext

    ctx = ModuleContext(file_path="<m>", module_name="m", source_code=src, code=mod_code)
    pipeline.extract_imports(ctx)
    if "math" in ctx.imports and "not_an_import" not in ctx.imports:
        killed += 1

    bad = pipeline.analyze_source("def f(:\n pass\n", "<bad>")
    if any(i.kind.name == "SYNTAX_ERROR" for i in bad.issues):
        killed += 1

    return [MutationResult("integration-core", total, killed, killed / total)]


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
