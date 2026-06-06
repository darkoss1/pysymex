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

"""Context-sensitive interprocedural analysis using k-limited call strings.

Traverses the call graph from entry points, creating per-context summaries
for each function.  Memoises results so each (function, context) pair is
analysed at most once.
"""

from __future__ import annotations

from types import CodeType

from pysymex.analysis.static.cross_function.call_graph import CallGraph
from pysymex.analysis.static.cross_function.effects import EffectAnalyzer
from pysymex.analysis.static.cross_function.return_types import infer_return_type
from pysymex.analysis.static.cross_function.types import CallContext, ContextSensitiveSummary


class ContextSensitiveAnalyzer:
    """K-limited call-string context-sensitive analyzer.

    Walks the call graph from entry points, computing per-context
    effect summaries and return types.  Summaries are memoised in
    ``self.summaries`` keyed by ``(function_name, CallContext)``.

    Attributes:
        k: Maximum call-string depth (longer strings are truncated).
        summaries: Memoised per-context results.
        call_graph: The call graph currently being analysed.
    """

    def __init__(self, k: int = 2) -> None:
        """Initialise with call-string depth *k*.

        Args:
            k: Maximum call-string length.  Defaults to 2.
        """
        self.k = k
        self.summaries: dict[tuple[str, CallContext], ContextSensitiveSummary] = {}
        self.call_graph: CallGraph | None = None

    def analyze(
        self,
        call_graph: CallGraph,
        code_objects: dict[str, CodeType],
    ) -> dict[tuple[str, CallContext], ContextSensitiveSummary]:
        """Analyse all reachable functions from *call_graph* entry points.

        Args:
            call_graph: The resolved call graph.
            code_objects: Map of function name to code object.

        Returns:
            A mapping of ``(function_name, CallContext)`` to
            :class:`ContextSensitiveSummary`.
        """
        self.call_graph = call_graph
        self.summaries = {}
        for entry in call_graph.entry_points:
            if entry in code_objects:
                self._analyze_function(entry, code_objects[entry], CallContext(), code_objects)
        return self.summaries

    def _analyze_function(
        self,
        func_name: str,
        code: CodeType,
        context: CallContext,
        code_objects: dict[str, CodeType],
    ) -> ContextSensitiveSummary:
        """Analyse *func_name* under *context*, memoising the result.

        Recursively analyses callees with extended contexts.  Already-visited
        ``(function, context)`` pairs return the cached summary immediately,
        preventing infinite recursion on recursive call graphs.
        """
        key = (func_name, context)
        if key in self.summaries:
            return self.summaries[key]

        summary = ContextSensitiveSummary(context=context, function=func_name)
        self.summaries[key] = summary
        effect_analyzer = EffectAnalyzer()
        summary.effect_summary = effect_analyzer.analyze_function(code, func_name)
        summary.return_type = infer_return_type(code)

        if self.call_graph:
            node = self.call_graph.nodes.get(func_name)
            if node:
                for call_site in node.callees:
                    callee = call_site.callee
                    if callee in code_objects:
                        new_context = context.extend(func_name, call_site.pc, self.k)
                        callee_summary = self._analyze_function(
                            callee,
                            code_objects[callee],
                            new_context,
                            code_objects,
                        )
                        if callee_summary.effect_summary and summary.effect_summary:
                            summary.effect_summary = summary.effect_summary.merge_with(
                                callee_summary.effect_summary
                            )
        return summary


__all__ = ["ContextSensitiveAnalyzer"]
