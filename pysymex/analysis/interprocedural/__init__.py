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

"""Interprocedural analysis exports."""

from pysymex.analysis.interprocedural.callgraph import (
    CallGraph as GraphCallGraph,
    CallGraphBuilder,
    CallGraphEdge,
    CallGraphNode,
)
from pysymex.analysis.interprocedural.cross_function import (
    CallContext,
    CallGraph,
    CallSite,
    CallType,
    ContextSensitiveAnalyzer,
    FunctionSummary,
    InterproceduralAnalyzer,
)
from pysymex.analysis.interprocedural.summaries import (
    SummaryAnalyzer,
    SummaryBuilder,
    SummaryRegistry,
    compose_summaries,
    create_builtin_summaries,
    instantiate_summary,
)
from pysymex.analysis.interprocedural.types import (
    CallGraphEdge,
    CallGraphNode,
)

__all__ = [
    "CallContext",
    "CallGraph",
    "CallGraphBuilder",
    "CallGraphEdge",
    "CallGraphNode",
    "CallSite",
    "CallType",
    "ContextSensitiveAnalyzer",
    "FunctionSummary",
    "GraphCallGraph",
    "InterproceduralAnalyzer",
    "SummaryAnalyzer",
    "SummaryBuilder",
    "SummaryRegistry",
    "compose_summaries",
    "create_builtin_summaries",
    "instantiate_summary",
]
