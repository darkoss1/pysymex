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

"""Orchestrate cross-function analysis: call graph, effects, escape, and context sensitivity.

Builds a call graph from module bytecode, then runs effect analysis,
escape analysis, and context-sensitive summarisation in a single pass.
"""

from __future__ import annotations

from types import CodeType

from pysymex.analysis.static.cross_function.call_graph.builder import CallGraphBuilder
from pysymex.analysis.static.cross_function.context import ContextSensitiveAnalyzer
from pysymex.analysis.static.cross_function.effects import EffectAnalyzer
from pysymex.analysis.static.cross_function.summary_cache import FunctionSummaryCache
from pysymex.analysis.static.code_objects import get_code_objects_with_context
from pysymex.analysis.static.escape import EscapeAnalyzer, EscapeInfo


class CrossFunctionAnalyzer:
    """Facade that coordinates call-graph construction, effect inference,
    escape analysis, and context-sensitive analysis.

    Owns a :class:`CallGraphBuilder`, :class:`EffectAnalyzer`,
    :class:`EscapeAnalyzer`, :class:`ContextSensitiveAnalyzer`, and
    :class:`FunctionSummaryCache` as long-lived components.
    """

    def __init__(self) -> None:
        """Initialize a CrossFunctionAnalyzer instance."""
        self.call_graph_builder = CallGraphBuilder()
        self.effect_analyzer = EffectAnalyzer()
        self.escape_analyzer = EscapeAnalyzer()
        self.context_analyzer = ContextSensitiveAnalyzer()
        self.function_summary_cache = FunctionSummaryCache()

    def analyze_module(self, module_code: CodeType) -> dict[str, object]:
        """Run all cross-function analyses on *module_code*.

        Args:
            module_code: The top-level module code object.

        Returns:
            A dict with keys ``"call_graph"``, ``"effects"``,
            ``"escape"``, and ``"context_sensitive"``, each mapping
            to the corresponding analysis result.
        """
        results: dict[str, object] = {}
        call_graph = self.call_graph_builder.build_from_module(module_code)
        results["call_graph"] = call_graph

        code_objects: dict[str, CodeType] = {"<module>": module_code}
        for code_object, _parent, full_path in get_code_objects_with_context(module_code):
            if full_path is None:
                continue
            code_objects[full_path] = code_object
            code_objects.setdefault(code_object.co_name, code_object)

        effect_summaries = self.effect_analyzer.analyze_with_call_graph(call_graph, code_objects)
        results["effects"] = effect_summaries

        escape_results: dict[str, dict[int, EscapeInfo]] = {}
        for name, code in code_objects.items():
            escape_results[name] = self.escape_analyzer.analyze_function(code)
        results["escape"] = escape_results

        results["context_sensitive"] = self.context_analyzer.analyze(call_graph, code_objects)
        return results


__all__ = ["CrossFunctionAnalyzer"]
