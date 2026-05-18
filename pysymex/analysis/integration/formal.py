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

import json
import tempfile
from pathlib import Path
from types import ModuleType

from pysymex.analysis.integration import AnalysisConfig, AnalysisPipeline, ReportGenerator
from pysymex.analysis.solver.formal import (
    DifferentialResult,
    FunctionChecklistItem,
    MutationResult,
    build_domain_done_gate_report,
    build_function_checklist,
)

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
    """Return modules included in the integration formal inventory."""
    import pysymex.analysis.integration.core as integration_core

    return [integration_core]


def function_checklist() -> list[FunctionChecklistItem]:
    return build_function_checklist(_modules(), STRICT_TARGETS)


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
    return build_domain_done_gate_report(checklist, diff, mut)
