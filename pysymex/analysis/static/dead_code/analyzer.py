# pysymex: python symbolic execution & formal verification
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

"""Orchestrator that runs all dead-code detectors on a function, module, or file."""

from __future__ import annotations

from pysymex.logger import get_logger
from types import CodeType

from pysymex.analysis.static.cross_function import CallGraphBuilder
from pysymex.analysis.static.dead_code.conditions import RedundantConditionDetector
from pysymex.analysis.static.dead_code.functions import UnusedFunctionDetector
from pysymex.analysis.static.dead_code.imports import UnusedImportDetector
from pysymex.analysis.static.dead_code.parameters import UnusedParameterDetector
from pysymex.analysis.static.dead_code.stores import DeadStoreDetector
from pysymex.analysis.static.dead_code.types import (
    DeadCode,
    DeadCodeKind,
    find_dataclass_class_names,
    get_class_method_names,
    is_class_body,
)
from pysymex.analysis.static.dead_code.unreachable import UnreachableCodeDetector
from pysymex.analysis.static.dead_code.variables import UnusedVariableDetector


class DeadCodeAnalyzer:
    """Runs unreachable code, unused variable, dead store, unused parameter,
    unused import, unused function, and redundant condition detectors.
    """

    def __init__(self) -> None:
        """Initialize the DeadCodeAnalyzer and its constituent detectors."""
        self.unreachable_detector = UnreachableCodeDetector()
        self.unused_var_detector = UnusedVariableDetector()
        self.dead_store_detector = DeadStoreDetector()
        self.unused_func_detector = UnusedFunctionDetector()
        self.unused_param_detector = UnusedParameterDetector()
        self.unused_import_detector = UnusedImportDetector()
        self.redundant_cond_detector = RedundantConditionDetector()

    def analyze_function(
        self,
        code: CodeType,
        file_path: str = "<unknown>",
    ) -> list[DeadCode]:
        """Run all per-function detectors on *code* and return combined findings."""
        results: list[DeadCode] = []
        results.extend(self.unreachable_detector.detect(code, file_path))
        results.extend(self.unused_var_detector.detect(code, file_path))
        results.extend(self.dead_store_detector.detect(code, file_path))
        results.extend(self.unused_param_detector.detect(code, file_path))
        results.extend(self.redundant_cond_detector.detect(code, file_path))
        return results

    def analyze_module(
        self,
        module_code: CodeType,
        source: str,
        file_path: str = "<unknown>",
    ) -> list[DeadCode]:
        """Run all detectors on *module_code*, including import and call-graph analysis."""
        results: list[DeadCode] = []
        results.extend(self.unused_import_detector.detect_from_source(source, file_path))
        results.extend(self.analyze_function(module_code, file_path))
        builder = CallGraphBuilder()
        call_graph = builder.build_from_module(module_code)
        results.extend(self.unused_func_detector.detect(call_graph, file_path))
        self._analyze_nested_functions(
            module_code,
            file_path,
            results,
            dataclass_names=find_dataclass_class_names(source),
        )
        return results

    def _analyze_nested_functions(
        self,
        code: CodeType,
        file_path: str,
        results: list[DeadCode],
        *,
        dataclass_names: set[str] | None = None,
    ) -> None:
        """Recursively descend into nested code objects, skipping dataclass auto-generated code."""
        for const in code.co_consts:
            if not hasattr(const, "co_code"):
                continue

            if is_class_body(const):
                is_dc = bool(dataclass_names and const.co_name in dataclass_names)

                if is_dc:
                    results.extend(self.unreachable_detector.detect(const, file_path))
                    results.extend(self.redundant_cond_detector.detect(const, file_path))
                else:
                    func_results = self.analyze_function(const, file_path)
                    method_names = get_class_method_names(const)
                    for dc in func_results:
                        if dc.kind == DeadCodeKind.UNUSED_VARIABLE and dc.name in method_names:
                            continue
                        results.append(dc)

                self._analyze_nested_functions(
                    const,
                    file_path,
                    results,
                    dataclass_names=dataclass_names,
                )
            else:
                results.extend(self.analyze_function(const, file_path))
                self._analyze_nested_functions(
                    const,
                    file_path,
                    results,
                    dataclass_names=dataclass_names,
                )

    def analyze_file(self, file_path: str) -> list[DeadCode]:
        """Read, compile, and analyse *file_path*; returns an error finding on syntax/runtime failure."""
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                source = f.read()
            code = compile(source, file_path, "exec")
            return self.analyze_module(code, source, file_path)
        except SyntaxError as e:
            return [
                DeadCode(
                    kind=DeadCodeKind.ANALYSIS_ERROR,
                    file=file_path,
                    line=e.lineno or 0,
                    message=f"Syntax error prevents analysis: {e.msg}",
                    confidence=0.0,
                )
            ]
        except Exception as exc:
            get_logger(__name__).debug("Dead code analysis failed for %s", file_path, exc_info=True)
            return [
                DeadCode(
                    kind=DeadCodeKind.ANALYSIS_ERROR,
                    file=file_path,
                    line=0,
                    message=f"Dead code analysis failed: {type(exc).__name__}: {exc}",
                    confidence=0.0,
                )
            ]


__all__ = ["DeadCodeAnalyzer"]
